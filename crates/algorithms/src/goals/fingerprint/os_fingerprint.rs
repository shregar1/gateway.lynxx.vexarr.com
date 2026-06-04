/// OS fingerprinting from TCP SYN packets.
///
/// Extracts a TCP signature (window size, TTL, DF bit, MSS, options hash)
/// from a raw SYN packet and matches it against known OS profiles.

pub struct TcpSignature {
    pub window: u16,
    pub ttl: u8,
    pub df: bool,
    pub mss: u16,
    pub options_hash: u32,
}

/// Extract a TCP fingerprint from a raw IPv4 SYN packet.
/// Expects the packet starting at the IP header.
/// Returns None if the packet is too short or not a SYN.
pub fn fingerprint_tcp(syn_packet: &[u8]) -> Option<TcpSignature> {
    // Minimum IP header = 20 bytes
    if syn_packet.len() < 40 {
        return None;
    }

    let version = syn_packet[0] >> 4;
    if version != 4 {
        return None;
    }

    let ihl = (syn_packet[0] & 0x0F) as usize * 4;
    if ihl < 20 || syn_packet.len() < ihl + 20 {
        return None;
    }

    let ttl = syn_packet[8];

    // DF bit: IP flags byte at offset 6, bit 1
    let df = (syn_packet[6] & 0x40) != 0;

    // Protocol must be TCP (6)
    if syn_packet[9] != 6 {
        return None;
    }

    let tcp = &syn_packet[ihl..];
    if tcp.len() < 20 {
        return None;
    }

    // TCP flags at offset 13: SYN must be set (bit 1)
    let flags = tcp[13];
    if flags & 0x02 == 0 {
        return None; // not a SYN
    }

    let window = u16::from_be_bytes([tcp[14], tcp[15]]);

    // TCP data offset (header length)
    let tcp_hdr_len = ((tcp[12] >> 4) as usize) * 4;

    // Parse TCP options for MSS and compute options hash
    let mut mss = 0u16;
    let mut options_hash = 0u32;

    if tcp_hdr_len > 20 && tcp.len() >= tcp_hdr_len {
        let options = &tcp[20..tcp_hdr_len];
        let mut i = 0;
        while i < options.len() {
            let kind = options[i];
            match kind {
                0 => break, // End of options
                1 => {
                    i += 1; // NOP
                    options_hash = options_hash.wrapping_mul(31).wrapping_add(1);
                }
                _ => {
                    if i + 1 >= options.len() {
                        break;
                    }
                    let len = options[i + 1] as usize;
                    if len < 2 || i + len > options.len() {
                        break;
                    }
                    options_hash = options_hash.wrapping_mul(31).wrapping_add(kind as u32);

                    if kind == 2 && len == 4 && i + 3 < options.len() {
                        mss = u16::from_be_bytes([options[i + 2], options[i + 3]]);
                    }

                    i += len;
                }
            }
        }
    }

    Some(TcpSignature {
        window,
        ttl,
        df,
        mss,
        options_hash,
    })
}

/// Match a TCP signature against known OS profiles.
/// Returns the best-guess OS name.
pub fn match_os(sig: &TcpSignature) -> &'static str {
    // Heuristic matching based on common OS defaults
    match (sig.ttl, sig.df, sig.window, sig.mss) {
        // Linux: TTL 64, DF set, MSS 1460
        (ttl, true, _, 1460) if ttl <= 64 && ttl > 32 => "Linux",
        // Windows: TTL 128, DF set, window 65535
        (ttl, true, 65535, _) if ttl <= 128 && ttl > 64 => "Windows",
        (ttl, true, _, _) if ttl <= 128 && ttl > 64 => "Windows",
        // macOS/iOS: TTL 64, DF set, window 65535
        (ttl, true, 65535, _) if ttl <= 64 && ttl > 32 => "macOS",
        // FreeBSD: TTL 64, DF set
        (ttl, true, _, 1460) if ttl <= 64 => "FreeBSD",
        // Cisco/network gear: TTL 255
        (ttl, _, _, _) if ttl > 128 => "Network Device",
        // Solaris: TTL 64, no DF
        (ttl, false, _, _) if ttl <= 64 && ttl > 32 => "Solaris",
        // Fallback
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_syn_packet(ttl: u8, df: bool, window: u16, mss: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 60]; // IP (20) + TCP (20) + Options (up to 20)

        // IP header
        pkt[0] = 0x45; // IPv4, IHL=5 (20 bytes)
        pkt[8] = ttl;
        pkt[9] = 6; // TCP
        if df {
            pkt[6] = 0x40;
        }

        // TCP header at offset 20
        pkt[33] = 0x02; // SYN flag
        pkt[34] = (window >> 8) as u8;
        pkt[35] = window as u8;

        // TCP data offset: 6 words (24 bytes = 20 header + 4 options)
        pkt[32] = 0x60;

        // MSS option: kind=2, len=4, value
        pkt[40] = 2;
        pkt[41] = 4;
        pkt[42] = (mss >> 8) as u8;
        pkt[43] = mss as u8;

        pkt
    }

    #[test]
    fn linux_fingerprint() {
        let pkt = make_syn_packet(64, true, 29200, 1460);
        let sig = fingerprint_tcp(&pkt).unwrap();
        assert_eq!(sig.ttl, 64);
        assert!(sig.df);
        assert_eq!(sig.mss, 1460);
        assert_eq!(match_os(&sig), "Linux");
    }

    #[test]
    fn windows_fingerprint() {
        let pkt = make_syn_packet(128, true, 65535, 1460);
        let sig = fingerprint_tcp(&pkt).unwrap();
        assert_eq!(match_os(&sig), "Windows");
    }

    #[test]
    fn too_short() {
        assert!(fingerprint_tcp(&[0x45; 10]).is_none());
    }

    #[test]
    fn not_syn() {
        let mut pkt = make_syn_packet(64, true, 29200, 1460);
        pkt[33] = 0x10; // ACK, not SYN
        assert!(fingerprint_tcp(&pkt).is_none());
    }

    #[test]
    fn not_tcp() {
        let mut pkt = make_syn_packet(64, true, 29200, 1460);
        pkt[9] = 17; // UDP
        assert!(fingerprint_tcp(&pkt).is_none());
    }
}
