/// MQTT CONNECT packet parser.
///
/// Parses the fixed header, variable header, and client-ID from an
/// MQTT CONNECT packet. Supports MQTT 3.1.1 and 5.0.

pub struct MqttConnect {
    pub client_id: String,
    pub version: u8,
    pub keep_alive: u16,
}

/// Parse an MQTT CONNECT packet from raw bytes.
/// Returns None if the packet is malformed or not a CONNECT.
pub fn parse_connect(data: &[u8]) -> Option<MqttConnect> {
    if data.len() < 2 {
        return None;
    }

    // Fixed header: packet type (high nibble) must be 1 (CONNECT)
    let pkt_type = data[0] >> 4;
    if pkt_type != 1 {
        return None;
    }

    // Remaining length (variable-length encoding)
    let (remaining_len, offset) = decode_remaining_length(&data[1..])?;
    let payload_start = 1 + offset;

    if data.len() < payload_start + remaining_len {
        return None;
    }

    let payload = &data[payload_start..payload_start + remaining_len];

    // Variable header: Protocol Name
    if payload.len() < 7 {
        return None;
    }

    let proto_name_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + proto_name_len + 4 {
        return None;
    }

    let proto_name = &payload[2..2 + proto_name_len];
    if proto_name != b"MQTT" && proto_name != b"MQIsdp" {
        return None;
    }

    let version = payload[2 + proto_name_len];
    // Connect flags at [2 + proto_name_len + 1]
    let _flags = payload[2 + proto_name_len + 1];
    let keep_alive = u16::from_be_bytes([
        payload[2 + proto_name_len + 2],
        payload[2 + proto_name_len + 3],
    ]);

    let mut pos = 2 + proto_name_len + 4;

    // MQTT 5.0 has properties after keep_alive
    if version == 5 {
        if pos >= payload.len() {
            return None;
        }
        let (prop_len, prop_offset) = decode_remaining_length(&payload[pos..])?;
        pos += prop_offset + prop_len;
    }

    // Payload: Client Identifier (UTF-8 encoded string)
    if pos + 2 > payload.len() {
        return None;
    }
    let client_id_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    if pos + client_id_len > payload.len() {
        return None;
    }
    let client_id = String::from_utf8(payload[pos..pos + client_id_len].to_vec()).ok()?;

    Some(MqttConnect {
        client_id,
        version,
        keep_alive,
    })
}

fn decode_remaining_length(data: &[u8]) -> Option<(usize, usize)> {
    let mut multiplier = 1usize;
    let mut value = 0usize;
    for (i, &byte) in data.iter().enumerate() {
        value += (byte as usize & 0x7F) * multiplier;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        multiplier *= 128;
        if i >= 3 {
            return None; // max 4 bytes
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_connect_v4(client_id: &str) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Variable header
        let mut var_hdr = Vec::new();
        // Protocol name "MQTT"
        var_hdr.extend_from_slice(&[0, 4]);
        var_hdr.extend_from_slice(b"MQTT");
        // Protocol level 4 (3.1.1)
        var_hdr.push(4);
        // Connect flags: clean session
        var_hdr.push(0x02);
        // Keep alive: 60s
        var_hdr.extend_from_slice(&60u16.to_be_bytes());
        // Client ID
        var_hdr.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        var_hdr.extend_from_slice(client_id.as_bytes());

        // Fixed header
        pkt.push(0x10); // CONNECT
        encode_remaining_length(&mut pkt, var_hdr.len());
        pkt.extend_from_slice(&var_hdr);
        pkt
    }

    fn encode_remaining_length(buf: &mut Vec<u8>, mut len: usize) {
        loop {
            let mut byte = (len % 128) as u8;
            len /= 128;
            if len > 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if len == 0 {
                break;
            }
        }
    }

    #[test]
    fn parse_v4_connect() {
        let pkt = make_connect_v4("test-client");
        let conn = parse_connect(&pkt).unwrap();
        assert_eq!(conn.client_id, "test-client");
        assert_eq!(conn.version, 4);
        assert_eq!(conn.keep_alive, 60);
    }

    #[test]
    fn not_connect_packet() {
        // PUBLISH packet type = 3
        assert!(parse_connect(&[0x30, 0x02, 0x00, 0x00]).is_none());
    }

    #[test]
    fn too_short() {
        assert!(parse_connect(&[0x10]).is_none());
    }

    #[test]
    fn empty_client_id() {
        let pkt = make_connect_v4("");
        let conn = parse_connect(&pkt).unwrap();
        assert_eq!(conn.client_id, "");
    }
}
