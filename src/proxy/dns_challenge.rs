use crate::error::GatewayError;
use async_trait::async_trait;
use std::sync::Arc;

const TXT_TTL: u32 = 120;
const PROPAGATION_POLL_SECS: u64 = 5;
const PROPAGATION_TIMEOUT_SECS: u64 = 120;

#[async_trait]
pub trait DnsProvider: Send + Sync + std::fmt::Debug {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError>;

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError>;

    fn provider_name(&self) -> &'static str;
}

// ── Cloudflare ──────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CloudflareDns {
    api_token: String,
    zone_id: String,
    client: reqwest::Client,
}

impl CloudflareDns {
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self {
            api_token,
            zone_id,
            client: reqwest::Client::new(),
        }
    }

    fn api_base(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        )
    }
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let body = serde_json::json!({
            "type": "TXT",
            "name": fqdn,
            "content": value,
            "ttl": TXT_TTL,
        });

        let resp = self
            .client
            .post(self.api_base())
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("cloudflare create TXT: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("cloudflare response body: {e}")))?;

        if !status.is_success() {
            return Err(GatewayError::Internal(format!(
                "cloudflare create TXT failed ({status}): {text}"
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| GatewayError::Internal(format!("cloudflare parse response: {e}")))?;

        let record_id = json["result"]["id"]
            .as_str()
            .ok_or_else(|| GatewayError::Internal("cloudflare: no record id in response".into()))?
            .to_string();

        tracing::info!(fqdn = %fqdn, record_id = %record_id, "cloudflare TXT record created");
        Ok(record_id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        let url = format!("{}/{record_id}", self.api_base());
        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("cloudflare delete TXT: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!(record_id = %record_id, "cloudflare delete TXT failed: {text}");
        } else {
            tracing::info!(record_id = %record_id, "cloudflare TXT record deleted");
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "cloudflare"
    }
}

// ── Route53 ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Route53Dns {
    hosted_zone_id: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    client: reqwest::Client,
}

impl Route53Dns {
    pub fn new(
        hosted_zone_id: String,
        region: String,
        access_key_id: String,
        secret_access_key: String,
    ) -> Self {
        Self {
            hosted_zone_id,
            region,
            access_key_id,
            secret_access_key,
            client: reqwest::Client::new(),
        }
    }

    fn change_batch_xml(&self, action: &str, fqdn: &str, value: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>
      <Change>
        <Action>{action}</Action>
        <ResourceRecordSet>
          <Name>{fqdn}</Name>
          <Type>TXT</Type>
          <TTL>{TTL_TTL}</TTL>
          <ResourceRecords>
            <ResourceRecord>
              <Value>"{value}"</Value>
            </ResourceRecord>
          </ResourceRecords>
        </ResourceRecordSet>
      </Change>
    </Changes>
  </ChangeBatch>
</ChangeResourceRecordSetsRequest>"#,
            action = action,
            fqdn = fqdn,
            TTL_TTL = TXT_TTL,
            value = value,
        )
    }

    async fn submit_change(
        &self,
        action: &str,
        fqdn: &str,
        value: &str,
    ) -> Result<(), GatewayError> {
        let url = format!(
            "https://route53.amazonaws.com/2013-04-01/hostedzone/{}/rrset",
            self.hosted_zone_id
        );
        let body = self.change_batch_xml(action, fqdn, value);

        let now = chrono::Utc::now();
        let date_str = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_short = now.format("%Y%m%d").to_string();

        let content_hash = hex_sha256(body.as_bytes());

        let canonical = format!(
            "POST\n/{}/rrset\n\ncontent-type:application/xml\nhost:route53.amazonaws.com\nx-amz-date:{}\n\ncontent-type;host;x-amz-date\n{}",
            format!("2013-04-01/hostedzone/{}", self.hosted_zone_id),
            date_str,
            content_hash
        );
        let scope = format!("{}/{}/route53/aws4_request", date_short, self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            date_str,
            scope,
            hex_sha256(canonical.as_bytes())
        );

        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key).as_bytes(),
            date_short.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"route53");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date, Signature={}",
            self.access_key_id, scope, signature
        );

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/xml")
            .header("X-Amz-Date", &date_str)
            .header("Authorization", &auth_header)
            .body(body)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("route53 {action}: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Internal(format!(
                "route53 {action} failed: {text}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for Route53Dns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        self.submit_change("UPSERT", fqdn, value).await?;
        tracing::info!(fqdn = %fqdn, "route53 TXT record upserted");
        Ok(format!("{fqdn}:{value}"))
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        let parts: Vec<&str> = record_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            tracing::warn!(record_id = %record_id, "route53: invalid record_id format for cleanup");
            return Ok(());
        }
        if let Err(e) = self.submit_change("DELETE", parts[0], parts[1]).await {
            tracing::warn!(error = %e, "route53 TXT cleanup failed (may already be deleted)");
        } else {
            tracing::info!(fqdn = %parts[0], "route53 TXT record deleted");
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "route53"
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn hex_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn build_acme_dns_name(domain: &str) -> String {
    format!("_acme-challenge.{domain}")
}

pub async fn wait_for_propagation(fqdn: &str, expected: &str) -> Result<(), GatewayError> {
    wait_for_propagation_with_timeout(fqdn, expected, PROPAGATION_TIMEOUT_SECS).await
}

pub async fn wait_for_propagation_with_timeout(
    fqdn: &str,
    expected: &str,
    timeout_secs: u64,
) -> Result<(), GatewayError> {
    let resolver = hickory_resolver::TokioAsyncResolver::tokio(
        hickory_resolver::config::ResolverConfig::default(),
        {
            let mut opts = hickory_resolver::config::ResolverOpts::default();
            // Disable negative caching so we detect freshly-created records
            // faster than the SOA minimum TTL would normally allow.
            opts.negative_min_ttl = Some(std::time::Duration::from_secs(0));
            opts.negative_max_ttl = Some(std::time::Duration::from_secs(5));
            opts
        },
    );

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(GatewayError::Internal(format!(
                "DNS propagation timeout for {fqdn} (waited {timeout_secs}s)"
            )));
        }

        if let Ok(lookup) = resolver.txt_lookup(fqdn).await {
            for record in lookup.iter() {
                let txt = record.to_string();
                if txt.trim_matches('"') == expected {
                    tracing::info!(fqdn = %fqdn, "DNS TXT record propagated");
                    return Ok(());
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(PROPAGATION_POLL_SECS)).await;
    }
}

// ── DigitalOcean ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct DigitalOceanDns {
    token: String,
    client: reqwest::Client,
}

impl DigitalOceanDns {
    pub fn new(token: String) -> Self {
        Self {
            token,
            client: reqwest::Client::new(),
        }
    }

    fn extract_domain(fqdn: &str) -> (&str, &str) {
        // Split "sub.example.com" into ("example.com", "sub").
        let parts: Vec<&str> = fqdn.rsplitn(3, '.').collect();
        if parts.len() >= 2 {
            let domain = &fqdn[fqdn.len() - parts[0].len() - parts[1].len() - 1..];
            let subdomain = &fqdn[..fqdn.len() - domain.len() - 1];
            (domain, subdomain)
        } else {
            (fqdn, "@")
        }
    }
}

#[async_trait]
impl DnsProvider for DigitalOceanDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let acme_fqdn = build_acme_dns_name(fqdn);
        let (domain, name) = Self::extract_domain(&acme_fqdn);

        let resp = self
            .client
            .post(format!(
                "https://api.digitalocean.com/v2/domains/{domain}/records"
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": name,
                "data": value,
                "ttl": TXT_TTL,
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("digitalocean api: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Internal(format!(
                "digitalocean dns create failed: {body}"
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| GatewayError::Internal(format!("digitalocean parse: {e}")))?;
        let id = json["domain_record"]["id"]
            .as_u64()
            .map(|n| format!("{domain}:{n}"))
            .unwrap_or_default();

        let _ = wait_for_propagation(&acme_fqdn, value).await;
        Ok(id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        if let Some((domain, id)) = record_id.split_once(':') {
            let _ = self
                .client
                .delete(format!(
                    "https://api.digitalocean.com/v2/domains/{domain}/records/{id}"
                ))
                .bearer_auth(&self.token)
                .send()
                .await;
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "digitalocean"
    }
}

// ── Google Cloud DNS ───────────────────────────────────────────────

#[derive(Debug)]
pub struct GoogleCloudDns {
    token: String,
    project: String,
    managed_zone: String,
    client: reqwest::Client,
}

impl GoogleCloudDns {
    pub fn new(token: String, project: String, managed_zone: String) -> Self {
        Self {
            token,
            project,
            managed_zone,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl DnsProvider for GoogleCloudDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        // fqdn is already `_acme-challenge.{domain}` from the caller
        let acme_fqdn = format!("{fqdn}.");
        let project = &self.project;
        let zone = &self.managed_zone;
        let url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{project}/managedZones/{zone}/changes",
        );

        // First try to delete any existing TXT record at this name so
        // we don't fail with "already exists" on retry / restart.
        if let Ok(existing) = self.lookup_txt(&acme_fqdn).await {
            tracing::debug!(fqdn = %acme_fqdn, "gcloud dns: removing stale TXT before create");
            let _ = self
                .client
                .post(&url)
                .bearer_auth(&self.token)
                .json(&serde_json::json!({
                    "deletions": [{
                        "name": &acme_fqdn,
                        "type": "TXT",
                        "ttl": TXT_TTL,
                        "rrdatas": existing,
                    }]
                }))
                .send()
                .await;
        }

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "additions": [{
                    "name": acme_fqdn,
                    "type": "TXT",
                    "ttl": TXT_TTL,
                    "rrdatas": [format!("\"{}\"", value)]
                }]
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("gcloud dns api: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Internal(format!(
                "gcloud dns create failed: {body}"
            )));
        }

        // Propagation is checked by the caller (issue_order); don't
        // duplicate the wait here — it wastes time against the DNS
        // negative-cache TTL window.
        Ok(acme_fqdn)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        let project = &self.project;
        let zone = &self.managed_zone;

        // record_id is the FQDN with trailing dot (e.g. "_acme-challenge.example.com.")
        if let Ok(existing) = self.lookup_txt(record_id).await {
            let resp = self
                .client
                .post(format!(
                    "https://dns.googleapis.com/dns/v1/projects/{project}/managedZones/{zone}/changes",
                ))
                .bearer_auth(&self.token)
                .json(&serde_json::json!({
                    "deletions": [{
                        "name": record_id,
                        "type": "TXT",
                        "ttl": TXT_TTL,
                        "rrdatas": existing,
                    }]
                }))
                .send()
                .await
                .map_err(|e| GatewayError::Internal(format!("gcloud dns cleanup: {e}")))?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!(record = %record_id, body = %body, "gcloud dns cleanup failed");
            } else {
                tracing::debug!(record = %record_id, "gcloud dns cleanup ok");
            }
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "gcloud"
    }
}

impl GoogleCloudDns {
    /// Look up existing TXT rrdatas for a record so we can delete it.
    async fn lookup_txt(&self, fqdn: &str) -> Result<Vec<String>, GatewayError> {
        let project = &self.project;
        let zone = &self.managed_zone;
        let resp = self
            .client
            .get(format!(
                "https://dns.googleapis.com/dns/v1/projects/{project}/managedZones/{zone}/rrsets/{fqdn}/TXT",
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("gcloud dns lookup: {e}")))?;

        if !resp.status().is_success() {
            return Err(GatewayError::Internal("no existing record".into()));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| GatewayError::Internal(format!("gcloud dns parse: {e}")))?;
        let rrdatas = body
            .get("rrdatas")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(rrdatas)
    }
}

// ── Hetzner ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct HetznerDns {
    api_token: String,
    zone_id: String,
    client: reqwest::Client,
}

impl HetznerDns {
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self {
            api_token,
            zone_id,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl DnsProvider for HetznerDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let acme_fqdn = build_acme_dns_name(fqdn);
        let resp = self
            .client
            .post("https://dns.hetzner.com/api/v1/records")
            .header("Auth-API-Token", &self.api_token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": acme_fqdn,
                "value": value,
                "zone_id": self.zone_id,
                "ttl": TXT_TTL,
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("hetzner create TXT: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("hetzner response body: {e}")))?;

        if !status.is_success() {
            return Err(GatewayError::Internal(format!(
                "hetzner create TXT failed ({status}): {text}"
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| GatewayError::Internal(format!("hetzner parse response: {e}")))?;

        let record_id = json["record"]["id"]
            .as_str()
            .ok_or_else(|| GatewayError::Internal("hetzner: no record id in response".into()))?
            .to_string();

        tracing::info!(fqdn = %acme_fqdn, record_id = %record_id, "hetzner TXT record created");
        Ok(record_id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        let resp = self
            .client
            .delete(format!(
                "https://dns.hetzner.com/api/v1/records/{record_id}"
            ))
            .header("Auth-API-Token", &self.api_token)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("hetzner delete TXT: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!(record_id = %record_id, "hetzner delete TXT failed: {text}");
        } else {
            tracing::info!(record_id = %record_id, "hetzner TXT record deleted");
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "hetzner"
    }
}

// ── Porkbun ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PorkbunDns {
    api_key: String,
    secret_key: String,
    client: reqwest::Client,
}

impl PorkbunDns {
    pub fn new(api_key: String, secret_key: String) -> Self {
        Self {
            api_key,
            secret_key,
            client: reqwest::Client::new(),
        }
    }

    /// Extract root domain from FQDN.  "sub.example.com" -> "example.com"
    fn extract_root_domain(fqdn: &str) -> &str {
        let parts: Vec<&str> = fqdn.rsplitn(3, '.').collect();
        if parts.len() >= 2 {
            &fqdn[fqdn.len() - parts[0].len() - parts[1].len() - 1..]
        } else {
            fqdn
        }
    }
}

#[async_trait]
impl DnsProvider for PorkbunDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let acme_fqdn = build_acme_dns_name(fqdn);
        let domain = Self::extract_root_domain(&acme_fqdn);
        let subdomain = if acme_fqdn.len() > domain.len() + 1 {
            &acme_fqdn[..acme_fqdn.len() - domain.len() - 1]
        } else {
            ""
        };

        let resp = self
            .client
            .post(format!(
                "https://api.porkbun.com/api/json/v3/dns/create/{domain}"
            ))
            .json(&serde_json::json!({
                "apikey": self.api_key,
                "secretapikey": self.secret_key,
                "type": "TXT",
                "name": subdomain,
                "content": value,
                "ttl": TXT_TTL.to_string(),
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("porkbun create TXT: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("porkbun response body: {e}")))?;

        if !status.is_success() {
            return Err(GatewayError::Internal(format!(
                "porkbun create TXT failed ({status}): {text}"
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| GatewayError::Internal(format!("porkbun parse response: {e}")))?;

        let record_id = json["id"]
            .as_u64()
            .map(|n| format!("{domain}:{n}"))
            .or_else(|| json["id"].as_str().map(|s| format!("{domain}:{s}")))
            .unwrap_or_else(|| format!("{domain}:unknown"));

        tracing::info!(fqdn = %acme_fqdn, record_id = %record_id, "porkbun TXT record created");
        Ok(record_id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        if let Some((domain, id)) = record_id.split_once(':') {
            let resp = self
                .client
                .post(format!(
                    "https://api.porkbun.com/api/json/v3/dns/delete/{domain}/{id}"
                ))
                .json(&serde_json::json!({
                    "apikey": self.api_key,
                    "secretapikey": self.secret_key,
                }))
                .send()
                .await
                .map_err(|e| GatewayError::Internal(format!("porkbun delete TXT: {e}")))?;

            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                tracing::warn!(record_id = %record_id, "porkbun delete TXT failed: {text}");
            } else {
                tracing::info!(record_id = %record_id, "porkbun TXT record deleted");
            }
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "porkbun"
    }
}

// ── Vultr ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct VultrDns {
    api_key: String,
    client: reqwest::Client,
}

impl VultrDns {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::new(),
        }
    }

    fn extract_domain(fqdn: &str) -> (&str, &str) {
        let parts: Vec<&str> = fqdn.rsplitn(3, '.').collect();
        if parts.len() >= 2 {
            let domain = &fqdn[fqdn.len() - parts[0].len() - parts[1].len() - 1..];
            let subdomain = if fqdn.len() > domain.len() + 1 {
                &fqdn[..fqdn.len() - domain.len() - 1]
            } else {
                ""
            };
            (domain, subdomain)
        } else {
            (fqdn, "@")
        }
    }
}

#[async_trait]
impl DnsProvider for VultrDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let acme_fqdn = build_acme_dns_name(fqdn);
        let (domain, name) = Self::extract_domain(&acme_fqdn);

        let resp = self
            .client
            .post(format!("https://api.vultr.com/v2/domains/{domain}/records"))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": name,
                "data": format!("\"{}\"", value),
                "ttl": TXT_TTL,
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("vultr create TXT: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("vultr response body: {e}")))?;

        if !status.is_success() {
            return Err(GatewayError::Internal(format!(
                "vultr create TXT failed ({status}): {text}"
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| GatewayError::Internal(format!("vultr parse response: {e}")))?;

        let record_id = json["record"]["id"]
            .as_str()
            .map(|s| format!("{domain}:{s}"))
            .unwrap_or_else(|| format!("{domain}:unknown"));

        tracing::info!(fqdn = %acme_fqdn, record_id = %record_id, "vultr TXT record created");
        Ok(record_id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        if let Some((domain, id)) = record_id.split_once(':') {
            let resp = self
                .client
                .delete(format!(
                    "https://api.vultr.com/v2/domains/{domain}/records/{id}"
                ))
                .bearer_auth(&self.api_key)
                .send()
                .await
                .map_err(|e| GatewayError::Internal(format!("vultr delete TXT: {e}")))?;

            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                tracing::warn!(record_id = %record_id, "vultr delete TXT failed: {text}");
            } else {
                tracing::info!(record_id = %record_id, "vultr TXT record deleted");
            }
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "vultr"
    }
}

// ── Namecheap ──────────────────────────────────────────────────────

#[derive(Debug)]
pub struct NamecheapDns {
    api_key: String,
    api_user: String,
    client_ip: String,
    client: reqwest::Client,
}

impl NamecheapDns {
    pub fn new(api_key: String, api_user: String, client_ip: String) -> Self {
        Self {
            api_key,
            api_user,
            client_ip,
            client: reqwest::Client::new(),
        }
    }

    fn extract_sld_tld(domain: &str) -> (&str, &str) {
        // "example.com" -> sld="example", tld="com"
        let parts: Vec<&str> = domain.rsplitn(2, '.').collect();
        if parts.len() == 2 {
            (parts[1], parts[0])
        } else {
            (domain, "")
        }
    }
}

#[async_trait]
impl DnsProvider for NamecheapDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let acme_fqdn = build_acme_dns_name(fqdn);
        let (domain, subdomain) = DigitalOceanDns::extract_domain(&acme_fqdn);
        let (sld, tld) = Self::extract_sld_tld(domain);

        let url = format!(
            "https://api.namecheap.com/xml.response?ApiUser={}&ApiKey={}&UserName={}&ClientIp={}&Command=namecheap.domains.dns.setHosts&SLD={}&TLD={}&HostName1={}&RecordType1=TXT&Address1={}&TTL1={}",
            self.api_user, self.api_key, self.api_user, self.client_ip,
            sld, tld, subdomain, value, TXT_TTL
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("namecheap create TXT: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("namecheap response body: {e}")))?;

        if !status.is_success() || text.contains("<Error>") {
            return Err(GatewayError::Internal(format!(
                "namecheap create TXT failed ({status}): {text}"
            )));
        }

        let record_id = format!("{acme_fqdn}:{value}");
        tracing::info!(fqdn = %acme_fqdn, "namecheap TXT record set");
        Ok(record_id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        // Namecheap replaces all host records on each setHosts call;
        // clearing requires re-setting without the TXT record. Log for
        // manual cleanup.
        tracing::debug!(record = %record_id, "namecheap TXT cleanup (manual re-set required)");
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "namecheap"
    }
}

// ── Azure DNS ──────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AzureDns {
    bearer_token: String,
    subscription_id: String,
    resource_group: String,
    zone_name: String,
    client: reqwest::Client,
}

impl AzureDns {
    pub fn new(
        bearer_token: String,
        subscription_id: String,
        resource_group: String,
        zone_name: String,
    ) -> Self {
        Self {
            bearer_token,
            subscription_id,
            resource_group,
            zone_name,
            client: reqwest::Client::new(),
        }
    }

    fn record_url(&self, record_name: &str) -> String {
        format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.subscription_id, self.resource_group, self.zone_name, record_name
        )
    }
}

#[async_trait]
impl DnsProvider for AzureDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let record_name = format!(
            "_acme-challenge.{}",
            fqdn.trim_end_matches(&format!(".{}", self.zone_name))
                .trim_end_matches('.')
        );
        let url = self.record_url(&record_name);

        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.bearer_token)
            .json(&serde_json::json!({
                "properties": {
                    "TTL": TXT_TTL,
                    "TXTRecords": [{
                        "value": [value]
                    }]
                }
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("azure dns create TXT: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("azure dns response body: {e}")))?;

        if !status.is_success() {
            return Err(GatewayError::Internal(format!(
                "azure dns create TXT failed ({status}): {text}"
            )));
        }

        tracing::info!(fqdn = %fqdn, record = %record_name, "azure dns TXT record created");
        Ok(record_name)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        let url = self.record_url(record_id);
        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&self.bearer_token)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("azure dns delete TXT: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!(record_id = %record_id, "azure dns delete TXT failed: {text}");
        } else {
            tracing::info!(record_id = %record_id, "azure dns TXT record deleted");
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "azure"
    }
}

// ── OVH ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct OvhDns {
    application_key: String,
    consumer_key: String,
    zone_name: String,
    client: reqwest::Client,
}

impl OvhDns {
    pub fn new(application_key: String, consumer_key: String, zone_name: String) -> Self {
        Self {
            application_key,
            consumer_key,
            zone_name,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl DnsProvider for OvhDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let subdomain = format!(
            "_acme-challenge.{}",
            fqdn.trim_end_matches(&format!(".{}", self.zone_name))
                .trim_end_matches('.')
        );

        let resp = self
            .client
            .post(format!(
                "https://api.ovh.com/1.0/domain/zone/{}/record",
                self.zone_name
            ))
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "fieldType": "TXT",
                "subDomain": subdomain,
                "target": value,
                "ttl": TXT_TTL,
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("ovh create TXT: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("ovh response body: {e}")))?;

        if !status.is_success() {
            return Err(GatewayError::Internal(format!(
                "ovh create TXT failed ({status}): {text}"
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| GatewayError::Internal(format!("ovh parse response: {e}")))?;

        let record_id = json["id"]
            .as_u64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".into());

        // Refresh the zone to apply changes.
        let _ = self
            .client
            .post(format!(
                "https://api.ovh.com/1.0/domain/zone/{}/refresh",
                self.zone_name
            ))
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .send()
            .await;

        tracing::info!(fqdn = %fqdn, record_id = %record_id, "ovh TXT record created");
        Ok(record_id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        let resp = self
            .client
            .delete(format!(
                "https://api.ovh.com/1.0/domain/zone/{}/record/{record_id}",
                self.zone_name
            ))
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("ovh delete TXT: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!(record_id = %record_id, "ovh delete TXT failed: {text}");
        } else {
            // Refresh zone after deletion.
            let _ = self
                .client
                .post(format!(
                    "https://api.ovh.com/1.0/domain/zone/{}/refresh",
                    self.zone_name
                ))
                .header("X-Ovh-Application", &self.application_key)
                .header("X-Ovh-Consumer", &self.consumer_key)
                .send()
                .await;
            tracing::info!(record_id = %record_id, "ovh TXT record deleted");
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "ovh"
    }
}

// ── DuckDNS ───────────────────────────────────────────────────────

#[derive(Debug)]
pub struct DuckDns {
    token: String,
    client: reqwest::Client,
}

impl DuckDns {
    pub fn new(token: String) -> Self {
        Self {
            token,
            client: reqwest::Client::new(),
        }
    }

    /// Extract the subdomain portion for DuckDNS.
    /// "myhost.duckdns.org" -> "myhost", "myhost" -> "myhost"
    fn extract_subdomain(fqdn: &str) -> &str {
        fqdn.strip_suffix(".duckdns.org").unwrap_or(fqdn)
    }
}

#[async_trait]
impl DnsProvider for DuckDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let domain = Self::extract_subdomain(fqdn);

        let resp = self
            .client
            .get(format!(
                "https://www.duckdns.org/update?domains={domain}&token={}&txt={value}&verbose=true",
                self.token
            ))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("duckdns set TXT: {e}")))?;

        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("duckdns response body: {e}")))?;

        if !text.starts_with("OK") {
            return Err(GatewayError::Internal(format!(
                "duckdns set TXT failed: {text}"
            )));
        }

        tracing::info!(domain = %domain, "duckdns TXT record set");
        Ok(format!("{domain}:{value}"))
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        if let Some((domain, _)) = record_id.split_once(':') {
            let resp = self
                .client
                .get(format!(
                    "https://www.duckdns.org/update?domains={domain}&token={}&txt=&clear=true",
                    self.token
                ))
                .send()
                .await
                .map_err(|e| GatewayError::Internal(format!("duckdns clear TXT: {e}")))?;

            let text = resp.text().await.unwrap_or_default();
            if !text.starts_with("OK") {
                tracing::warn!(domain = %domain, "duckdns clear TXT failed: {text}");
            } else {
                tracing::info!(domain = %domain, "duckdns TXT record cleared");
            }
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "duckdns"
    }
}

// ── Linode ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct LinodeDns {
    token: String,
    domain_id: String,
    client: reqwest::Client,
}

impl LinodeDns {
    pub fn new(token: String, domain_id: String) -> Self {
        Self {
            token,
            domain_id,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl DnsProvider for LinodeDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let acme_name = build_acme_dns_name(fqdn);

        let resp = self
            .client
            .post(format!(
                "https://api.linode.com/v4/domains/{}/records",
                self.domain_id
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": acme_name,
                "target": value,
                "ttl_sec": TXT_TTL,
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("linode create TXT: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Internal(format!("linode response body: {e}")))?;

        if !status.is_success() {
            return Err(GatewayError::Internal(format!(
                "linode create TXT failed ({status}): {text}"
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| GatewayError::Internal(format!("linode parse response: {e}")))?;

        let record_id = json["id"]
            .as_u64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".into());

        tracing::info!(fqdn = %acme_name, record_id = %record_id, "linode TXT record created");
        Ok(record_id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        let resp = self
            .client
            .delete(format!(
                "https://api.linode.com/v4/domains/{}/records/{record_id}",
                self.domain_id
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("linode delete TXT: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!(record_id = %record_id, "linode delete TXT failed: {text}");
        } else {
            tracing::info!(record_id = %record_id, "linode TXT record deleted");
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "linode"
    }
}

// ── Gandi ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct GandiDns {
    token: String,
    client: reqwest::Client,
}

impl GandiDns {
    pub fn new(token: String) -> Self {
        Self {
            token,
            client: reqwest::Client::new(),
        }
    }

    fn extract_domain(fqdn: &str) -> (&str, &str) {
        let parts: Vec<&str> = fqdn.rsplitn(3, '.').collect();
        if parts.len() >= 2 {
            let domain = &fqdn[fqdn.len() - parts[0].len() - parts[1].len() - 1..];
            let subdomain = if fqdn.len() > domain.len() + 1 {
                &fqdn[..fqdn.len() - domain.len() - 1]
            } else {
                "@"
            };
            (domain, subdomain)
        } else {
            (fqdn, "@")
        }
    }
}

#[async_trait]
impl DnsProvider for GandiDns {
    async fn set_txt_record(&self, fqdn: &str, value: &str) -> Result<String, GatewayError> {
        let acme_fqdn = build_acme_dns_name(fqdn);
        let (domain, name) = Self::extract_domain(&acme_fqdn);

        let resp = self
            .client
            .put(format!(
                "https://api.gandi.net/v5/livedns/domains/{domain}/records/{name}/TXT"
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "rrset_values": [value],
                "rrset_ttl": TXT_TTL,
            }))
            .send()
            .await
            .map_err(|e| GatewayError::Internal(format!("gandi create TXT: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Internal(format!(
                "gandi create TXT failed ({status}): {text}"
            )));
        }

        let record_id = format!("{domain}:{name}");
        tracing::info!(fqdn = %acme_fqdn, record_id = %record_id, "gandi TXT record created");
        Ok(record_id)
    }

    async fn clear_txt_record(&self, record_id: &str) -> Result<(), GatewayError> {
        if let Some((domain, name)) = record_id.split_once(':') {
            let resp = self
                .client
                .delete(format!(
                    "https://api.gandi.net/v5/livedns/domains/{domain}/records/{name}/TXT"
                ))
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|e| GatewayError::Internal(format!("gandi delete TXT: {e}")))?;

            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                tracing::warn!(record_id = %record_id, "gandi delete TXT failed: {text}");
            } else {
                tracing::info!(record_id = %record_id, "gandi TXT record deleted");
            }
        }
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "gandi"
    }
}

pub fn from_config(cfg: &crate::config::Dns01Config) -> Result<Arc<dyn DnsProvider>, GatewayError> {
    match cfg.provider.as_str() {
        "cloudflare" => {
            if cfg.api_token.is_empty() || cfg.zone_id.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 cloudflare requires api_token and zone_id".into(),
                ));
            }
            Ok(Arc::new(CloudflareDns::new(
                cfg.api_token.clone(),
                cfg.zone_id.clone(),
            )))
        }
        "route53" => {
            if cfg.hosted_zone_id.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 route53 requires hosted_zone_id".into(),
                ));
            }
            let access_key = if cfg.access_key_id.is_empty() {
                std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default()
            } else {
                cfg.access_key_id.clone()
            };
            let secret_key = if cfg.secret_access_key.is_empty() {
                std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default()
            } else {
                cfg.secret_access_key.clone()
            };
            let region = if cfg.region.is_empty() {
                std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into())
            } else {
                cfg.region.clone()
            };
            Ok(Arc::new(Route53Dns::new(
                cfg.hosted_zone_id.clone(),
                region,
                access_key,
                secret_key,
            )))
        }
        "digitalocean" => {
            let token = if cfg.api_token.is_empty() {
                std::env::var("DIGITALOCEAN_TOKEN").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            if token.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 digitalocean requires api_token or DIGITALOCEAN_TOKEN env".into(),
                ));
            }
            Ok(Arc::new(DigitalOceanDns::new(token)))
        }
        "gcloud" | "google" | "google-cloud" => {
            let token = if cfg.api_token.is_empty() {
                std::env::var("GCLOUD_DNS_TOKEN").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            let project = std::env::var("GCLOUD_PROJECT").unwrap_or_default();
            let managed_zone = if cfg.zone_id.is_empty() {
                std::env::var("GCLOUD_DNS_ZONE").unwrap_or_default()
            } else {
                cfg.zone_id.clone()
            };
            if token.is_empty() || project.is_empty() || managed_zone.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 gcloud requires api_token (or GCLOUD_DNS_TOKEN), GCLOUD_PROJECT, and zone_id (or GCLOUD_DNS_ZONE)".into(),
                ));
            }
            Ok(Arc::new(GoogleCloudDns::new(token, project, managed_zone)))
        }
        "hetzner" => {
            let token = if cfg.api_token.is_empty() {
                std::env::var("HETZNER_DNS_TOKEN").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            let zone = if cfg.zone_id.is_empty() {
                std::env::var("HETZNER_DNS_ZONE_ID").unwrap_or_default()
            } else {
                cfg.zone_id.clone()
            };
            if token.is_empty() || zone.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 hetzner requires api_token and zone_id".into(),
                ));
            }
            Ok(Arc::new(HetznerDns::new(token, zone)))
        }
        "porkbun" => {
            // api_token = api_key, secret_access_key = secret_key
            let api_key = if cfg.api_token.is_empty() {
                std::env::var("PORKBUN_API_KEY").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            let secret_key = if cfg.secret_access_key.is_empty() {
                std::env::var("PORKBUN_SECRET_KEY").unwrap_or_default()
            } else {
                cfg.secret_access_key.clone()
            };
            if api_key.is_empty() || secret_key.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 porkbun requires api_token (api_key) and secret_access_key (secret_key)".into(),
                ));
            }
            Ok(Arc::new(PorkbunDns::new(api_key, secret_key)))
        }
        "vultr" => {
            let token = if cfg.api_token.is_empty() {
                std::env::var("VULTR_API_KEY").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            if token.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 vultr requires api_token".into(),
                ));
            }
            Ok(Arc::new(VultrDns::new(token)))
        }
        "namecheap" => {
            let api_key = if cfg.api_token.is_empty() {
                std::env::var("NAMECHEAP_API_KEY").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            let api_user = if cfg.access_key_id.is_empty() {
                std::env::var("NAMECHEAP_API_USER").unwrap_or_default()
            } else {
                cfg.access_key_id.clone()
            };
            let client_ip = if cfg.region.is_empty() {
                std::env::var("NAMECHEAP_CLIENT_IP").unwrap_or_default()
            } else {
                // Reuse region field for client IP.
                cfg.region.clone()
            };
            if api_key.is_empty() || api_user.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 namecheap requires api_token (api_key) and access_key_id (api_user)".into(),
                ));
            }
            Ok(Arc::new(NamecheapDns::new(api_key, api_user, client_ip)))
        }
        "azure" | "azure-dns" => {
            let token = if cfg.api_token.is_empty() {
                std::env::var("AZURE_DNS_TOKEN").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            // subscription_id in hosted_zone_id, resource_group in region, zone in zone_id
            let subscription_id = if cfg.hosted_zone_id.is_empty() {
                std::env::var("AZURE_SUBSCRIPTION_ID").unwrap_or_default()
            } else {
                cfg.hosted_zone_id.clone()
            };
            let resource_group = if cfg.region.is_empty() {
                std::env::var("AZURE_RESOURCE_GROUP").unwrap_or_default()
            } else {
                cfg.region.clone()
            };
            let zone_name = if cfg.zone_id.is_empty() {
                std::env::var("AZURE_DNS_ZONE").unwrap_or_default()
            } else {
                cfg.zone_id.clone()
            };
            if token.is_empty() || subscription_id.is_empty() || zone_name.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 azure requires api_token, hosted_zone_id (subscription_id), and zone_id (zone name)".into(),
                ));
            }
            Ok(Arc::new(AzureDns::new(
                token,
                subscription_id,
                resource_group,
                zone_name,
            )))
        }
        "ovh" => {
            // application_key in api_token, consumer_key in secret_access_key
            let app_key = if cfg.api_token.is_empty() {
                std::env::var("OVH_APPLICATION_KEY").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            let consumer_key = if cfg.secret_access_key.is_empty() {
                std::env::var("OVH_CONSUMER_KEY").unwrap_or_default()
            } else {
                cfg.secret_access_key.clone()
            };
            let zone_name = if cfg.zone_id.is_empty() {
                std::env::var("OVH_DNS_ZONE").unwrap_or_default()
            } else {
                cfg.zone_id.clone()
            };
            if app_key.is_empty() || consumer_key.is_empty() || zone_name.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 ovh requires api_token (application_key), secret_access_key (consumer_key), and zone_id".into(),
                ));
            }
            Ok(Arc::new(OvhDns::new(app_key, consumer_key, zone_name)))
        }
        "duckdns" => {
            let token = if cfg.api_token.is_empty() {
                std::env::var("DUCKDNS_TOKEN").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            if token.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 duckdns requires api_token".into(),
                ));
            }
            Ok(Arc::new(DuckDns::new(token)))
        }
        "linode" => {
            let token = if cfg.api_token.is_empty() {
                std::env::var("LINODE_TOKEN").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            let domain_id = if cfg.zone_id.is_empty() {
                std::env::var("LINODE_DOMAIN_ID").unwrap_or_default()
            } else {
                cfg.zone_id.clone()
            };
            if token.is_empty() || domain_id.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 linode requires api_token and zone_id (domain_id)".into(),
                ));
            }
            Ok(Arc::new(LinodeDns::new(token, domain_id)))
        }
        "gandi" => {
            let token = if cfg.api_token.is_empty() {
                std::env::var("GANDI_TOKEN").unwrap_or_default()
            } else {
                cfg.api_token.clone()
            };
            if token.is_empty() {
                return Err(GatewayError::ConfigError(
                    "dns-01 gandi requires api_token (Personal Access Token)".into(),
                ));
            }
            Ok(Arc::new(GandiDns::new(token)))
        }
        other => Err(GatewayError::ConfigError(format!(
            "unknown dns-01 provider: {other} (supported: cloudflare, route53, digitalocean, gcloud, hetzner, porkbun, vultr, namecheap, azure, ovh, duckdns, linode, gandi)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acme_dns_name() {
        assert_eq!(
            build_acme_dns_name("example.com"),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn cloudflare_provider_name() {
        let p = CloudflareDns::new("tok".into(), "zone".into());
        assert_eq!(p.provider_name(), "cloudflare");
    }

    #[test]
    fn route53_provider_name() {
        let p = Route53Dns::new("zone".into(), "us-east-1".into(), "ak".into(), "sk".into());
        assert_eq!(p.provider_name(), "route53");
    }

    #[test]
    fn route53_change_batch_xml() {
        let p = Route53Dns::new("Z123".into(), "us-east-1".into(), "ak".into(), "sk".into());
        let xml = p.change_batch_xml("UPSERT", "_acme-challenge.example.com", "test-value");
        assert!(xml.contains("UPSERT"));
        assert!(xml.contains("_acme-challenge.example.com"));
        assert!(xml.contains("\"test-value\""));
        assert!(xml.contains("TXT"));
    }

    #[test]
    fn hex_sha256_known_vector() {
        let result = hex_sha256(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ── Provider name tests ────────────────────────────────────────

    #[test]
    fn hetzner_provider_name() {
        let p = HetznerDns::new("tok".into(), "zone".into());
        assert_eq!(p.provider_name(), "hetzner");
    }

    #[test]
    fn porkbun_provider_name() {
        let p = PorkbunDns::new("ak".into(), "sk".into());
        assert_eq!(p.provider_name(), "porkbun");
    }

    #[test]
    fn vultr_provider_name() {
        let p = VultrDns::new("key".into());
        assert_eq!(p.provider_name(), "vultr");
    }

    #[test]
    fn namecheap_provider_name() {
        let p = NamecheapDns::new("key".into(), "user".into(), "127.0.0.1".into());
        assert_eq!(p.provider_name(), "namecheap");
    }

    #[test]
    fn azure_provider_name() {
        let p = AzureDns::new("tok".into(), "sub".into(), "rg".into(), "zone".into());
        assert_eq!(p.provider_name(), "azure");
    }

    #[test]
    fn ovh_provider_name() {
        let p = OvhDns::new("ak".into(), "ck".into(), "zone".into());
        assert_eq!(p.provider_name(), "ovh");
    }

    #[test]
    fn duckdns_provider_name() {
        let p = DuckDns::new("tok".into());
        assert_eq!(p.provider_name(), "duckdns");
    }

    #[test]
    fn linode_provider_name() {
        let p = LinodeDns::new("tok".into(), "12345".into());
        assert_eq!(p.provider_name(), "linode");
    }

    #[test]
    fn gandi_provider_name() {
        let p = GandiDns::new("tok".into());
        assert_eq!(p.provider_name(), "gandi");
    }

    // ── from_config recognises new providers ───────────────────────

    fn test_cfg(provider: &str) -> crate::config::Dns01Config {
        crate::config::Dns01Config {
            provider: provider.into(),
            api_token: "test-token".into(),
            zone_id: "test-zone".into(),
            hosted_zone_id: "test-hosted-zone".into(),
            region: "us-east-1".into(),
            access_key_id: "ak".into(),
            secret_access_key: "sk".into(),
            ..Default::default()
        }
    }

    #[test]
    fn from_config_hetzner() {
        let p = from_config(&test_cfg("hetzner")).unwrap();
        assert_eq!(p.provider_name(), "hetzner");
    }

    #[test]
    fn from_config_porkbun() {
        let p = from_config(&test_cfg("porkbun")).unwrap();
        assert_eq!(p.provider_name(), "porkbun");
    }

    #[test]
    fn from_config_vultr() {
        let p = from_config(&test_cfg("vultr")).unwrap();
        assert_eq!(p.provider_name(), "vultr");
    }

    #[test]
    fn from_config_namecheap() {
        let p = from_config(&test_cfg("namecheap")).unwrap();
        assert_eq!(p.provider_name(), "namecheap");
    }

    #[test]
    fn from_config_azure() {
        let p = from_config(&test_cfg("azure")).unwrap();
        assert_eq!(p.provider_name(), "azure");
    }

    #[test]
    fn from_config_azure_dns_alias() {
        let p = from_config(&test_cfg("azure-dns")).unwrap();
        assert_eq!(p.provider_name(), "azure");
    }

    #[test]
    fn from_config_ovh() {
        let p = from_config(&test_cfg("ovh")).unwrap();
        assert_eq!(p.provider_name(), "ovh");
    }

    #[test]
    fn from_config_duckdns() {
        let p = from_config(&test_cfg("duckdns")).unwrap();
        assert_eq!(p.provider_name(), "duckdns");
    }

    #[test]
    fn from_config_linode() {
        let p = from_config(&test_cfg("linode")).unwrap();
        assert_eq!(p.provider_name(), "linode");
    }

    #[test]
    fn from_config_gandi() {
        let p = from_config(&test_cfg("gandi")).unwrap();
        assert_eq!(p.provider_name(), "gandi");
    }

    // ── from_config errors on missing credentials ──────────────────

    fn empty_cfg(provider: &str) -> crate::config::Dns01Config {
        crate::config::Dns01Config {
            provider: provider.into(),
            ..Default::default()
        }
    }

    #[test]
    fn from_config_hetzner_missing_creds() {
        let err = from_config(&empty_cfg("hetzner")).unwrap_err();
        assert!(format!("{err}").contains("hetzner"));
    }

    #[test]
    fn from_config_porkbun_missing_creds() {
        let err = from_config(&empty_cfg("porkbun")).unwrap_err();
        assert!(format!("{err}").contains("porkbun"));
    }

    #[test]
    fn from_config_vultr_missing_creds() {
        let err = from_config(&empty_cfg("vultr")).unwrap_err();
        assert!(format!("{err}").contains("vultr"));
    }

    #[test]
    fn from_config_namecheap_missing_creds() {
        let err = from_config(&empty_cfg("namecheap")).unwrap_err();
        assert!(format!("{err}").contains("namecheap"));
    }

    #[test]
    fn from_config_azure_missing_creds() {
        let err = from_config(&empty_cfg("azure")).unwrap_err();
        assert!(format!("{err}").contains("azure"));
    }

    #[test]
    fn from_config_ovh_missing_creds() {
        let err = from_config(&empty_cfg("ovh")).unwrap_err();
        assert!(format!("{err}").contains("ovh"));
    }

    #[test]
    fn from_config_duckdns_missing_creds() {
        let err = from_config(&empty_cfg("duckdns")).unwrap_err();
        assert!(format!("{err}").contains("duckdns"));
    }

    #[test]
    fn from_config_linode_missing_creds() {
        let err = from_config(&empty_cfg("linode")).unwrap_err();
        assert!(format!("{err}").contains("linode"));
    }

    #[test]
    fn from_config_gandi_missing_creds() {
        let err = from_config(&empty_cfg("gandi")).unwrap_err();
        assert!(format!("{err}").contains("gandi"));
    }

    #[test]
    fn from_config_unknown_provider() {
        let err = from_config(&empty_cfg("nonexistent")).unwrap_err();
        assert!(format!("{err}").contains("unknown"));
    }

    // ── Domain extraction logic ────────────────────────────────────

    #[test]
    fn vultr_extract_domain_simple() {
        let (domain, sub) = VultrDns::extract_domain("_acme-challenge.example.com");
        assert_eq!(domain, "example.com");
        assert_eq!(sub, "_acme-challenge");
    }

    #[test]
    fn vultr_extract_domain_nested() {
        let (domain, sub) = VultrDns::extract_domain("_acme-challenge.sub.example.com");
        assert_eq!(domain, "example.com");
        assert_eq!(sub, "_acme-challenge.sub");
    }

    #[test]
    fn porkbun_extract_root_domain() {
        assert_eq!(
            PorkbunDns::extract_root_domain("_acme-challenge.example.com"),
            "example.com"
        );
        assert_eq!(
            PorkbunDns::extract_root_domain("example.com"),
            "example.com"
        );
    }

    #[test]
    fn gandi_extract_domain() {
        let (domain, sub) = GandiDns::extract_domain("_acme-challenge.example.com");
        assert_eq!(domain, "example.com");
        assert_eq!(sub, "_acme-challenge");
    }

    #[test]
    fn duckdns_extract_subdomain() {
        assert_eq!(DuckDns::extract_subdomain("myhost.duckdns.org"), "myhost");
        assert_eq!(DuckDns::extract_subdomain("myhost"), "myhost");
    }

    #[test]
    fn namecheap_extract_sld_tld() {
        let (sld, tld) = NamecheapDns::extract_sld_tld("example.com");
        assert_eq!(sld, "example");
        assert_eq!(tld, "com");
    }
}
