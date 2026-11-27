//! OCSP stapling for inbound TLS.
//!
//! When a certificate's Authority Information Access (AIA) extension
//! contains an OCSP responder URL, we fetch a signed OCSP response and
//! attach it to the [`CertifiedKey`] so rustls can staple it during the
//! TLS handshake. A background task re-fetches before the response
//! expires.
//!
//! If the OCSP fetch fails for any reason — network, parse, responder
//! error — we log a warning and continue without stapling. This is the
//! correct behaviour: OCSP stapling is a "should" in RFC 6066, and
//! clients that care will fall back to their own OCSP lookup.

use crate::error::GatewayError;
use rustls::sign::CertifiedKey;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Hasher for the OCSP response cache. Keys are SHA-256 fingerprints
/// of the server cert chain — not attacker-influenced — so ahash gives
/// the typical 2-5× speedup over SipHash on the 32-byte fingerprint
/// without giving up any meaningful security property.
type FastHasher = ahash::RandomState;

/// How often the background refresher wakes up (6 hours).
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// HTTP timeout for a single OCSP request.
const OCSP_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// ── OID constants (DER-encoded dotted values) ────────────────────────

/// id-ad-ocsp  1.3.6.1.5.5.7.48.1
const OID_AD_OCSP: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1];

// ── SHA-1 (FIPS 180-4) ──────────────────────────────────────────────
//
// OCSP CertIDs mandate SHA-1 (RFC 6960 §4.1.1). We don't have a `sha1`
// crate in the dep tree so we implement the hash directly. This is the
// unmodified FIPS 180-4 algorithm — no creativity, no shortcuts.

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    // Pre-processing: pad message
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

// ── ASN.1 / DER helpers ─────────────────────────────────────────────

/// Encode a DER tag-length-value.
fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_push_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Push a DER length encoding onto `buf`.
fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Encode an OID as DER (tag 0x06).
fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = Vec::new();
    if arcs.len() >= 2 {
        body.push((arcs[0] * 40 + arcs[1]) as u8);
        for &arc in &arcs[2..] {
            der_encode_base128(&mut body, arc);
        }
    }
    der_tlv(0x06, &body)
}

/// Base-128 variable-length encoding used by DER OIDs.
fn der_encode_base128(buf: &mut Vec<u8>, mut value: u64) {
    if value == 0 {
        buf.push(0);
        return;
    }
    let mut tmp = Vec::new();
    while value > 0 {
        tmp.push((value & 0x7F) as u8);
        value >>= 7;
    }
    tmp.reverse();
    for (i, b) in tmp.iter().enumerate() {
        if i < tmp.len() - 1 {
            buf.push(b | 0x80);
        } else {
            buf.push(*b);
        }
    }
}

// ── OCSP request builder ────────────────────────────────────────────

/// Build a DER-encoded OCSPRequest for a single certificate.
///
/// Minimal structure (RFC 6960 §4.1.1):
/// ```text
/// OCSPRequest ::= SEQUENCE {
///   tbsRequest TBSRequest }
///
/// TBSRequest ::= SEQUENCE {
///   requestList SEQUENCE OF Request }
///
/// Request ::= SEQUENCE {
///   reqCert CertID }
///
/// CertID ::= SEQUENCE {
///   hashAlgorithm  AlgorithmIdentifier,  -- SHA-1
///   issuerNameHash OCTET STRING,
///   issuerKeyHash  OCTET STRING,
///   serialNumber   INTEGER }
/// ```
fn build_ocsp_request(
    issuer_name_hash: &[u8],
    issuer_key_hash: &[u8],
    serial_number: &[u8],
) -> Vec<u8> {
    // AlgorithmIdentifier for SHA-1: SEQUENCE { OID 1.3.14.3.2.26, NULL }
    let sha1_oid = der_oid(&[1, 3, 14, 3, 2, 26]);
    let null = vec![0x05, 0x00];
    let mut alg_id_body = Vec::new();
    alg_id_body.extend_from_slice(&sha1_oid);
    alg_id_body.extend_from_slice(&null);
    let alg_id = der_tlv(0x30, &alg_id_body); // SEQUENCE

    let name_hash = der_tlv(0x04, issuer_name_hash); // OCTET STRING
    let key_hash = der_tlv(0x04, issuer_key_hash); // OCTET STRING
    let serial = der_tlv(0x02, serial_number); // INTEGER

    // CertID
    let mut cert_id_body = Vec::new();
    cert_id_body.extend_from_slice(&alg_id);
    cert_id_body.extend_from_slice(&name_hash);
    cert_id_body.extend_from_slice(&key_hash);
    cert_id_body.extend_from_slice(&serial);
    let cert_id = der_tlv(0x30, &cert_id_body);

    // Request
    let request = der_tlv(0x30, &cert_id);

    // requestList (SEQUENCE OF Request)
    let request_list = der_tlv(0x30, &request);

    // TBSRequest
    let tbs_request = der_tlv(0x30, &request_list);

    // OCSPRequest
    der_tlv(0x30, &tbs_request)
}

// ── OCSP response parsing (minimal) ────────────────────────────────

/// Successful OCSP response status (RFC 6960 §4.2.1).
const OCSP_RESPONSE_STATUS_SUCCESSFUL: u8 = 0;

/// Minimally parse an OCSP response to extract the `nextUpdate` time so
/// we know when to refresh. Returns `None` if the response is malformed
/// or doesn't contain a nextUpdate.
///
/// We also verify the top-level response status is "successful" (0).
fn parse_ocsp_next_update(response_der: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    // OCSPResponse ::= SEQUENCE {
    //   responseStatus ENUMERATED,
    //   responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL }
    let (rest, seq) = read_der_sequence(response_der)?;
    let _ = rest;
    let (rest, status_bytes) = read_der_element(seq)?;
    // ENUMERATED tag = 0x0A
    if status_bytes.is_empty() {
        return None;
    }
    // The full TLV was consumed; we need the tag. Re-parse from seq.
    let tag = seq[0];
    if tag != 0x0A {
        return None;
    }
    // Check status value
    let status_val = parse_der_enumerated(seq)?;
    if status_val != OCSP_RESPONSE_STATUS_SUCCESSFUL {
        return None;
    }

    // responseBytes [0] EXPLICIT
    let (_, response_bytes_explicit) = read_der_element(rest)?;
    if response_bytes_explicit.is_empty() {
        return None;
    }
    // Unwrap the EXPLICIT [0] wrapper
    let (_, response_bytes_seq) =
        read_der_sequence(strip_explicit_tag(response_bytes_explicit, 0)?)?;

    // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
    let (rest2, _response_type) = read_der_element(response_bytes_seq)?;
    let (_, response_octet) = read_der_element(rest2)?;
    // The OCTET STRING wraps the inner content
    let response_content = read_der_content(response_octet)?;

    // BasicOCSPResponse ::= SEQUENCE { tbsResponseData ..., ... }
    let (_, basic_seq) = read_der_sequence(response_content)?;
    let (_, tbs_data_seq) = read_der_sequence(basic_seq)?;

    // TBSResponseData may start with [0] EXPLICIT version.
    // Then: responderID, producedAt, responses SEQUENCE OF ...
    let mut cursor = tbs_data_seq;

    // Skip optional [0] version
    if !cursor.is_empty() && (cursor[0] & 0xE0) == 0xA0 && (cursor[0] & 0x1F) == 0 {
        let (rest, _) = read_der_element(cursor)?;
        cursor = rest;
    }

    // Skip responderID (could be [1] or [2] tagged)
    let (rest, _) = read_der_element(cursor)?;
    cursor = rest;

    // Skip producedAt (GeneralizedTime)
    let (rest, _) = read_der_element(cursor)?;
    cursor = rest;

    // responses SEQUENCE OF SingleResponse
    let (_, responses_seq) = read_der_sequence(cursor)?;

    // First SingleResponse
    let (_, single_resp_seq) = read_der_sequence(responses_seq)?;

    // SingleResponse ::= SEQUENCE {
    //   certID CertID,
    //   certStatus ...,
    //   thisUpdate GeneralizedTime,
    //   nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL }
    let mut sr_cursor = single_resp_seq;

    // Skip certID (SEQUENCE)
    let (rest, _) = read_der_element(sr_cursor)?;
    sr_cursor = rest;

    // Skip certStatus
    let (rest, _) = read_der_element(sr_cursor)?;
    sr_cursor = rest;

    // Skip thisUpdate
    let (rest, _) = read_der_element(sr_cursor)?;
    sr_cursor = rest;

    // nextUpdate [0] EXPLICIT GeneralizedTime
    if sr_cursor.is_empty() {
        return None;
    }
    let next_update_explicit = strip_explicit_tag(sr_cursor, 0)?;
    let (_, time_bytes) = read_der_element(next_update_explicit)?;
    let time_content = read_der_content(time_bytes)?;
    let time_str = std::str::from_utf8(time_content).ok()?;
    parse_generalized_time(time_str)
}

/// Parse a GeneralizedTime string (YYYYMMDDHHMMSSZ) into a DateTime.
fn parse_generalized_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone, Utc};
    // Common formats: "20250101120000Z" or "20250101120000.000Z"
    let s = s.trim_end_matches('Z');
    let s = s.split('.').next()?; // drop fractional seconds
    let naive = NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%S").ok()?;
    Some(Utc.from_utc_datetime(&naive))
}

/// Read a DER TLV element, returning (remaining, full_tlv_bytes).
fn read_der_element(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let (content_len, header_len) = der_read_length(&data[1..])?;
    let total = 1 + header_len + content_len;
    if data.len() < total {
        return None;
    }
    Some((&data[total..], &data[..total]))
}

/// Read a DER SEQUENCE, returning (remaining_after_seq, sequence_content).
fn read_der_sequence(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() || (data[0] & 0x1F) != 0x10 {
        return None;
    }
    let (content_len, header_len) = der_read_length(&data[1..])?;
    let start = 1 + header_len;
    let end = start + content_len;
    if data.len() < end {
        return None;
    }
    Some((&data[end..], &data[start..end]))
}

/// Get the content bytes from a full TLV (skip tag + length).
fn read_der_content(tlv: &[u8]) -> Option<&[u8]> {
    if tlv.is_empty() {
        return None;
    }
    let (content_len, header_len) = der_read_length(&tlv[1..])?;
    let start = 1 + header_len;
    let end = start + content_len;
    if tlv.len() < end {
        return None;
    }
    Some(&tlv[start..end])
}

/// Parse a DER length field, returning (length_value, bytes_consumed).
fn der_read_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut len: usize = 0;
        for &b in &data[1..1 + num_bytes] {
            len = len.checked_shl(8)?.checked_add(b as usize)?;
        }
        Some((len, 1 + num_bytes))
    }
}

/// Strip an EXPLICIT context-specific wrapper tag [n].
fn strip_explicit_tag(data: &[u8], expected_tag_num: u8) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    // Context-specific, constructed: 0xA0 | tag_num
    if tag != (0xA0 | expected_tag_num) {
        return None;
    }
    let (content_len, header_len) = der_read_length(&data[1..])?;
    let start = 1 + header_len;
    let end = start + content_len;
    if data.len() < end {
        return None;
    }
    Some(&data[start..end])
}

/// Parse a DER ENUMERATED value.
fn parse_der_enumerated(tlv: &[u8]) -> Option<u8> {
    if tlv.is_empty() || tlv[0] != 0x0A {
        return None;
    }
    let content = read_der_content(tlv)?;
    if content.len() == 1 {
        Some(content[0])
    } else {
        None
    }
}

// ── AIA extraction ──────────────────────────────────────────────────

/// Extract the OCSP responder URL from the certificate's Authority
/// Information Access extension. Returns `None` if the extension is
/// absent or contains no OCSP access method.
fn extract_ocsp_responder_url(cert_der: &[u8]) -> Option<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    let (_, parsed) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    for ext in parsed.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                let method_str = desc.access_method.to_id_string();
                // id-ad-ocsp = 1.3.6.1.5.5.7.48.1
                if method_str == oid_arcs_to_dotted(OID_AD_OCSP) {
                    if let GeneralName::URI(uri) = &desc.access_location {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Format OID arcs as a dotted string for comparison with x509-parser.
fn oid_arcs_to_dotted(arcs: &[u64]) -> String {
    arcs.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Extract the issuer's Subject Key Identifier from the *issuer*
/// certificate (second cert in the chain). If the chain only has a leaf
/// we can't compute the issuer key hash from the chain alone. In that
/// case the caller must hash the issuer's Subject Public Key Info from
/// the leaf's issuer field — but realistically the chain should contain
/// the issuer.
fn extract_issuer_public_key_bytes(issuer_der: &[u8]) -> Option<Vec<u8>> {
    let (_, parsed) = x509_parser::parse_x509_certificate(issuer_der).ok()?;
    let spki = parsed
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec();
    Some(spki)
}

// ── Cache key ───────────────────────────────────────────────────────

/// Fingerprint a certificate chain for use as a cache key.
fn chain_fingerprint(cert_chain: &[rustls::pki_types::CertificateDer<'_>]) -> Vec<u8> {
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    for cert in cert_chain {
        hasher.update(cert.as_ref());
    }
    hasher.finalize().to_vec()
}

// ── Cached entry ────────────────────────────────────────────────────

#[derive(Clone)]
struct CachedOcsp {
    /// Raw DER-encoded OCSPResponse.
    response: Vec<u8>,
    /// When the response becomes stale (`nextUpdate`).
    expires: Option<chrono::DateTime<chrono::Utc>>,
}

// ── Public API ──────────────────────────────────────────────────────

/// OCSP stapler that fetches, caches, and refreshes OCSP responses.
pub struct OcspStapler {
    cache: RwLock<HashMap<Vec<u8>, CachedOcsp, FastHasher>>,
    http: reqwest::Client,
}

impl Default for OcspStapler {
    fn default() -> Self {
        Self::new()
    }
}

impl OcspStapler {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(OCSP_HTTP_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            cache: RwLock::new(HashMap::with_hasher(FastHasher::default())),
            http,
        }
    }

    /// Fetch (or return cached) OCSP response for the given cert chain
    /// and return a new [`CertifiedKey`] with the OCSP response attached.
    ///
    /// On any failure, logs a warning and returns the original key
    /// unchanged (no stapling).
    pub async fn staple(
        &self,
        certified_key: &Arc<CertifiedKey>,
    ) -> Result<Arc<CertifiedKey>, GatewayError> {
        let fp = chain_fingerprint(&certified_key.cert);

        // Fast path: check cache.
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&fp) {
                let still_valid = cached
                    .expires
                    .map(|exp| chrono::Utc::now() < exp)
                    .unwrap_or(true);
                if still_valid {
                    return Ok(self.attach_ocsp(certified_key, cached.response.clone()));
                }
            }
        }

        // Slow path: fetch from responder.
        match self.fetch_and_cache(certified_key, &fp).await {
            Ok(response) => Ok(self.attach_ocsp(certified_key, response)),
            Err(e) => {
                tracing::warn!(error = %e, "ocsp stapling failed, continuing without");
                Ok(Arc::clone(certified_key))
            }
        }
    }

    /// Spawn a background task that refreshes cached OCSP responses
    /// every [`REFRESH_INTERVAL`].
    ///
    /// `certs` is the set of certified keys to keep stapled. The task
    /// runs until the `shutdown` signal fires (or forever if `None`).
    pub fn spawn_refresher(
        self: &Arc<Self>,
        certs: Vec<Arc<CertifiedKey>>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let stapler = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REFRESH_INTERVAL);
            // The first tick fires immediately — skip it so we don't
            // double-fetch right after startup.
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = shutdown_signal(&shutdown) => {
                        tracing::info!("ocsp refresher shutting down");
                        return;
                    }
                }

                for ck in &certs {
                    let fp = chain_fingerprint(&ck.cert);
                    if let Err(e) = stapler.fetch_and_cache(ck, &fp).await {
                        tracing::warn!(error = %e, "ocsp refresh failed");
                    } else {
                        tracing::debug!("ocsp response refreshed");
                    }
                }
            }
        });
    }

    // ── internals ───────────────────────────────────────────────────

    fn attach_ocsp(&self, key: &Arc<CertifiedKey>, ocsp: Vec<u8>) -> Arc<CertifiedKey> {
        let mut new_key = CertifiedKey::new(key.cert.clone(), Arc::clone(&key.key));
        new_key.ocsp = Some(ocsp);
        Arc::new(new_key)
    }

    async fn fetch_and_cache(
        &self,
        certified_key: &Arc<CertifiedKey>,
        fingerprint: &[u8],
    ) -> Result<Vec<u8>, GatewayError> {
        let leaf = certified_key
            .end_entity_cert()
            .map_err(|e| GatewayError::Internal(format!("no leaf cert: {e}")))?;

        // 1. Extract OCSP responder URL from AIA.
        let responder_url = extract_ocsp_responder_url(leaf.as_ref())
            .ok_or_else(|| GatewayError::Internal("no OCSP responder URL in AIA".into()))?;

        // 2. Parse leaf to get serial number and issuer name.
        let (_, leaf_parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
            .map_err(|e| GatewayError::Internal(format!("parse leaf cert: {e}")))?;

        let serial_bytes = leaf_parsed.tbs_certificate.raw_serial();

        // 3. Compute issuer name hash (SHA-1 of the DER-encoded issuer
        //    Name from the leaf certificate).
        let issuer_name_der = leaf_parsed.tbs_certificate.issuer.as_raw();
        let issuer_name_hash = sha1(issuer_name_der);

        // 4. Compute issuer key hash. If the chain has an issuer cert,
        //    hash its SubjectPublicKey; otherwise we can't proceed.
        let issuer_key_hash = if certified_key.cert.len() >= 2 {
            let issuer_der = certified_key.cert[1].as_ref();
            let pubkey = extract_issuer_public_key_bytes(issuer_der)
                .ok_or_else(|| GatewayError::Internal("can't extract issuer pubkey".into()))?;
            sha1(&pubkey)
        } else {
            // Single-cert chain (self-signed or missing issuer). Hash
            // the leaf's own public key as a last resort — some OCSP
            // responders accept this for self-signed certs.
            let pubkey = leaf_parsed
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .to_vec();
            sha1(&pubkey)
        };

        // 5. Build and send the OCSP request.
        let ocsp_req = build_ocsp_request(&issuer_name_hash, &issuer_key_hash, serial_bytes);

        let http_resp = self
            .http
            .post(&responder_url)
            .header("Content-Type", "application/ocsp-request")
            .body(ocsp_req)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("ocsp http request: {e}")))?;

        if !http_resp.status().is_success() {
            return Err(GatewayError::Internal(format!(
                "ocsp responder returned {}",
                http_resp.status()
            )));
        }

        let ocsp_response = http_resp
            .bytes()
            .await
            .map_err(|e| GatewayError::Internal(format!("ocsp read body: {e}")))?
            .to_vec();

        // 6. Parse nextUpdate for cache expiry.
        let expires = parse_ocsp_next_update(&ocsp_response);

        // 7. Cache.
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                fingerprint.to_vec(),
                CachedOcsp {
                    response: ocsp_response.clone(),
                    expires,
                },
            );
        }

        Ok(ocsp_response)
    }
}

/// Wait until the shutdown watch channel signals `true`.
async fn shutdown_signal(rx: &tokio::sync::watch::Receiver<bool>) {
    let mut rx = rx.clone();
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            // Sender dropped — treat as shutdown.
            return;
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DER helpers ─────────────────────────────────────────────────

    #[test]
    fn der_tlv_short_length() {
        let result = der_tlv(0x04, &[0xAA, 0xBB]);
        assert_eq!(result, vec![0x04, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn der_tlv_medium_length() {
        let payload = vec![0x42; 200];
        let result = der_tlv(0x04, &payload);
        assert_eq!(result[0], 0x04);
        assert_eq!(result[1], 0x81);
        assert_eq!(result[2], 200);
        assert_eq!(result.len(), 3 + 200);
    }

    #[test]
    fn der_tlv_long_length() {
        let payload = vec![0x42; 300];
        let result = der_tlv(0x04, &payload);
        assert_eq!(result[0], 0x04);
        assert_eq!(result[1], 0x82);
        assert_eq!(result[2], 0x01); // 300 >> 8
        assert_eq!(result[3], 0x2C); // 300 & 0xFF
        assert_eq!(result.len(), 4 + 300);
    }

    #[test]
    fn der_oid_sha1() {
        // OID 1.3.14.3.2.26 (SHA-1)
        let result = der_oid(&[1, 3, 14, 3, 2, 26]);
        // First octet: 1*40 + 3 = 43 = 0x2B
        // Then: 14, 3, 2, 26
        assert_eq!(result[0], 0x06); // OID tag
        assert_eq!(result[1], 0x05); // length = 5
        assert_eq!(result[2], 0x2B); // 1.3
        assert_eq!(result[3], 0x0E); // 14
        assert_eq!(result[4], 0x03); // 3
        assert_eq!(result[5], 0x02); // 2
        assert_eq!(result[6], 0x1A); // 26
    }

    #[test]
    fn der_oid_ocsp() {
        // OID 1.3.6.1.5.5.7.48.1
        let result = der_oid(OID_AD_OCSP);
        assert_eq!(result[0], 0x06); // OID tag
                                     // 1.3 -> 0x2B, 6 -> 0x06, 1 -> 0x01, 5 -> 0x05, 5 -> 0x05,
                                     // 7 -> 0x07, 48 -> 0x30, 1 -> 0x01
        let expected_body = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
        assert_eq!(result[1], expected_body.len() as u8);
        assert_eq!(&result[2..], &expected_body);
    }

    #[test]
    fn base128_single_byte() {
        let mut buf = Vec::new();
        der_encode_base128(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);
    }

    #[test]
    fn base128_two_bytes() {
        let mut buf = Vec::new();
        der_encode_base128(&mut buf, 128);
        assert_eq!(buf, vec![0x81, 0x00]);
    }

    // ── OCSP request structure ──────────────────────────────────────

    #[test]
    fn ocsp_request_is_valid_der() {
        let name_hash = [0xAA; 20];
        let key_hash = [0xBB; 20];
        let serial = [0x01, 0x02, 0x03];
        let req = build_ocsp_request(&name_hash, &key_hash, &serial);

        // Must start with SEQUENCE tag
        assert_eq!(req[0], 0x30, "OCSPRequest must be a SEQUENCE");

        // Should be parseable by our own DER reader
        let (remaining, _) = read_der_sequence(&req).expect("valid DER SEQUENCE");
        assert!(remaining.is_empty(), "no trailing bytes");
    }

    #[test]
    fn ocsp_request_contains_serial() {
        let name_hash = [0xAA; 20];
        let key_hash = [0xBB; 20];
        let serial = [0x42, 0x43, 0x44];
        let req = build_ocsp_request(&name_hash, &key_hash, &serial);

        // The serial bytes should appear inside the request
        assert!(
            req.windows(3).any(|w| w == serial),
            "serial number must appear in the OCSP request"
        );
    }

    #[test]
    fn ocsp_request_contains_hashes() {
        let name_hash = [0xDE; 20];
        let key_hash = [0xAD; 20];
        let serial = [0x01];
        let req = build_ocsp_request(&name_hash, &key_hash, &serial);

        assert!(
            req.windows(20).any(|w| w == name_hash),
            "issuer name hash must appear"
        );
        assert!(
            req.windows(20).any(|w| w == key_hash),
            "issuer key hash must appear"
        );
    }

    // ── DER parsing helpers ─────────────────────────────────────────

    #[test]
    fn read_length_short() {
        assert_eq!(der_read_length(&[0x05]), Some((5, 1)));
        assert_eq!(der_read_length(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn read_length_long_form() {
        // 0x81 0xC8 = 200
        assert_eq!(der_read_length(&[0x81, 0xC8]), Some((200, 2)));
        // 0x82 0x01 0x00 = 256
        assert_eq!(der_read_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
    }

    #[test]
    fn read_length_empty() {
        assert_eq!(der_read_length(&[]), None);
    }

    #[test]
    fn read_der_element_basic() {
        // OCTET STRING containing [0xAA, 0xBB]
        let data = [0x04, 0x02, 0xAA, 0xBB, 0xFF]; // trailing byte
        let (rest, elem) = read_der_element(&data).unwrap();
        assert_eq!(elem, &[0x04, 0x02, 0xAA, 0xBB]);
        assert_eq!(rest, &[0xFF]);
    }

    #[test]
    fn read_der_sequence_basic() {
        let inner = [0x04, 0x01, 0xAA]; // OCTET STRING
        let seq = der_tlv(0x30, &inner);
        let (rest, content) = read_der_sequence(&seq).unwrap();
        assert!(rest.is_empty());
        assert_eq!(content, &inner);
    }

    // ── GeneralizedTime parsing ─────────────────────────────────────

    #[test]
    fn parse_generalized_time_basic() {
        let dt = parse_generalized_time("20250715120000Z").unwrap();
        assert_eq!(dt.to_rfc3339(), "2025-07-15T12:00:00+00:00");
    }

    #[test]
    fn parse_generalized_time_fractional() {
        let dt = parse_generalized_time("20251231235959.999Z").unwrap();
        assert_eq!(dt.to_rfc3339(), "2025-12-31T23:59:59+00:00");
    }

    #[test]
    fn parse_generalized_time_invalid() {
        assert!(parse_generalized_time("not-a-date").is_none());
    }

    // ── OID formatting ──────────────────────────────────────────────

    #[test]
    fn oid_dotted_format() {
        assert_eq!(oid_arcs_to_dotted(OID_AD_OCSP), "1.3.6.1.5.5.7.48.1");
    }

    // ── Cache fingerprint ───────────────────────────────────────────

    #[test]
    fn fingerprint_deterministic() {
        let cert_data = rustls::pki_types::CertificateDer::from(vec![0x30, 0x00]);
        let chain = vec![cert_data];
        let fp1 = chain_fingerprint(&chain);
        let fp2 = chain_fingerprint(&chain);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 32); // SHA-256
    }

    #[test]
    fn fingerprint_differs_for_different_chains() {
        let chain_a = vec![rustls::pki_types::CertificateDer::from(vec![0x30, 0x01])];
        let chain_b = vec![rustls::pki_types::CertificateDer::from(vec![0x30, 0x02])];
        assert_ne!(chain_fingerprint(&chain_a), chain_fingerprint(&chain_b));
    }

    // ── OCSP response parsing ───────────────────────────────────────

    #[test]
    fn parse_ocsp_next_update_garbage() {
        assert!(parse_ocsp_next_update(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn parse_ocsp_next_update_empty() {
        assert!(parse_ocsp_next_update(&[]).is_none());
    }

    /// Build a minimal synthetic OCSPResponse with a known nextUpdate.
    /// This exercises the full parsing path.
    #[test]
    fn parse_ocsp_next_update_synthetic() {
        let next_update_str = b"20260101120000Z";

        // Work inside-out to build the DER structure.

        // CertID (dummy)
        let cert_id = der_tlv(0x30, &der_tlv(0x30, &[0x05, 0x00]));

        // certStatus: good [0] IMPLICIT NULL = tag 0x80, len 0
        let cert_status = vec![0x80, 0x00];

        // thisUpdate: GeneralizedTime
        let this_update = der_tlv(0x18, b"20250701120000Z");

        // nextUpdate: [0] EXPLICIT GeneralizedTime
        let next_update_time = der_tlv(0x18, next_update_str);
        let next_update = der_tlv(0xA0, &next_update_time);

        // SingleResponse
        let mut single_resp_body = Vec::new();
        single_resp_body.extend_from_slice(&cert_id);
        single_resp_body.extend_from_slice(&cert_status);
        single_resp_body.extend_from_slice(&this_update);
        single_resp_body.extend_from_slice(&next_update);
        let single_resp = der_tlv(0x30, &single_resp_body);

        // responses SEQUENCE OF SingleResponse
        let responses = der_tlv(0x30, &single_resp);

        // responderID: [1] EXPLICIT — use a dummy
        let responder_id = der_tlv(0xA1, &der_tlv(0x30, &[0x05, 0x00]));

        // producedAt
        let produced_at = der_tlv(0x18, b"20250701120000Z");

        // tbsResponseData (no version)
        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&responder_id);
        tbs_body.extend_from_slice(&produced_at);
        tbs_body.extend_from_slice(&responses);
        let tbs = der_tlv(0x30, &tbs_body);

        // signatureAlgorithm (dummy)
        let sig_alg = der_tlv(0x30, &der_oid(&[1, 2, 840, 113549, 1, 1, 11]));

        // signature (dummy BIT STRING)
        let sig = der_tlv(0x03, &[0x00, 0xAA]);

        // BasicOCSPResponse
        let mut basic_body = Vec::new();
        basic_body.extend_from_slice(&tbs);
        basic_body.extend_from_slice(&sig_alg);
        basic_body.extend_from_slice(&sig);
        let basic = der_tlv(0x30, &basic_body);

        // ResponseBytes: SEQUENCE { OID id-pkix-ocsp-basic, OCTET STRING(basic) }
        let resp_type_oid = der_oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]);
        let resp_octet = der_tlv(0x04, &basic);
        let mut resp_bytes_body = Vec::new();
        resp_bytes_body.extend_from_slice(&resp_type_oid);
        resp_bytes_body.extend_from_slice(&resp_octet);
        let resp_bytes = der_tlv(0x30, &resp_bytes_body);

        // Wrap in [0] EXPLICIT
        let resp_bytes_explicit = der_tlv(0xA0, &resp_bytes);

        // responseStatus: ENUMERATED 0 (successful)
        let status = der_tlv(0x0A, &[0x00]);

        // OCSPResponse
        let mut ocsp_body = Vec::new();
        ocsp_body.extend_from_slice(&status);
        ocsp_body.extend_from_slice(&resp_bytes_explicit);
        let ocsp_response = der_tlv(0x30, &ocsp_body);

        let parsed = parse_ocsp_next_update(&ocsp_response);
        assert!(
            parsed.is_some(),
            "should parse nextUpdate from synthetic response"
        );
        let dt = parsed.unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-01-01T12:00:00+00:00");
    }

    #[test]
    fn parse_ocsp_non_successful_status() {
        // OCSPResponse with status = 1 (malformedRequest)
        let status = der_tlv(0x0A, &[0x01]);
        let ocsp = der_tlv(0x30, &status);
        assert!(
            parse_ocsp_next_update(&ocsp).is_none(),
            "non-successful status should return None"
        );
    }

    // ── strip_explicit_tag ──────────────────────────────────────────

    #[test]
    fn strip_explicit_tag_valid() {
        let inner = [0x02, 0x01, 0x05]; // INTEGER 5
        let wrapped = der_tlv(0xA0, &inner);
        let result = strip_explicit_tag(&wrapped, 0).unwrap();
        assert_eq!(result, &inner);
    }

    #[test]
    fn strip_explicit_tag_wrong_number() {
        let inner = [0x02, 0x01, 0x05];
        let wrapped = der_tlv(0xA0, &inner);
        assert!(strip_explicit_tag(&wrapped, 1).is_none());
    }

    #[test]
    fn strip_explicit_tag_empty() {
        assert!(strip_explicit_tag(&[], 0).is_none());
    }

    // ── SHA-1 correctness ────────────────────────────────────────────

    #[test]
    fn sha1_empty_input() {
        // FIPS 180-4 test vector: SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hash = sha1(b"");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_abc() {
        // FIPS 180-4 test vector: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let hash = sha1(b"abc");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn sha1_longer_message() {
        // SHA-1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 84983e441c3bd26ebaae4aa1f95129e5e54670f1
        let hash = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    // ── OcspStapler construction ────────────────────────────────────

    #[test]
    fn stapler_creates_without_panic() {
        let _stapler = OcspStapler::new();
    }

    // ── AIA extraction (requires a real cert with AIA) ──────────────

    #[test]
    fn extract_ocsp_url_returns_none_for_self_signed() {
        // Self-signed certs (like our ACME challenge certs) won't have AIA.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ck = crate::proxy::tls_alpn::build_challenge_cert("example.com", "auth").unwrap();
        let url = extract_ocsp_responder_url(ck.cert[0].as_ref());
        assert!(
            url.is_none(),
            "self-signed cert should have no AIA/OCSP URL"
        );
    }
}
