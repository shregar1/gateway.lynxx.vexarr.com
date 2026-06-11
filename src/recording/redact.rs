//! Redaction helpers used before a `Recording` is persisted.
//!
//! Two strategies are supported:
//!
//! - `redact_headers` matches header names case-insensitively and replaces
//!   the value with `[redacted]`. Used for `Authorization`, cookies, etc.
//! - `redact_body_paths` walks a `serde_json::Value` and replaces any
//!   object key whose name matches one of the configured paths. The match
//!   is by *key name* anywhere in the tree, not by JSON pointer — that's
//!   intentional, so `password` redacts every `password` field regardless
//!   of nesting.

use serde_json::Value;

/// Headers that always carry credentials/secrets. These are redacted in
/// recordings regardless of operator config — a recorder must never persist
/// them in the clear even if the user forgot to list them.
pub const ALWAYS_SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-amz-security-token",
    "x-csrf-token",
    "x-xsrf-token",
];

/// Form/query parameter names whose values are always redacted in recorded
/// non-JSON (form-urlencoded) bodies.
pub const ALWAYS_SENSITIVE_FORM_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "authorization",
    "code",
];

/// Redact configured headers in-place to `[redacted]`. Header name match is
/// case-insensitive.
pub fn redact_headers(headers: &mut Vec<(String, String)>, names: &[String]) {
    for (k, v) in headers.iter_mut() {
        if names.iter().any(|n| n.eq_ignore_ascii_case(k)) {
            *v = "[redacted]".into();
        }
    }
}

/// Like [`redact_headers`] but also always redacts [`ALWAYS_SENSITIVE_HEADERS`]
/// (Authorization, Cookie, Set-Cookie, …). Use this for everything persisted
/// to a recording so credentials never leak even with empty config.
pub fn redact_headers_defaulted(headers: &mut Vec<(String, String)>, extra: &[String]) {
    for (k, v) in headers.iter_mut() {
        let sensitive = ALWAYS_SENSITIVE_HEADERS
            .iter()
            .any(|n| n.eq_ignore_ascii_case(k))
            || extra.iter().any(|n| n.eq_ignore_ascii_case(k));
        if sensitive {
            *v = "[redacted]".into();
        }
    }
}

/// Redact sensitive values in an `application/x-www-form-urlencoded` body,
/// returning re-encoded bytes. Caller must only invoke this when the body is
/// actually form-encoded (it re-serialises, which would corrupt other bodies).
pub fn redact_form_urlencoded(body: &[u8], extra_keys: &[String]) -> Vec<u8> {
    if std::str::from_utf8(body).is_err() {
        return body.to_vec();
    }
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in url::form_urlencoded::parse(body) {
        let sensitive = ALWAYS_SENSITIVE_FORM_KEYS
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&k))
            || extra_keys.iter().any(|n| n.eq_ignore_ascii_case(&k));
        if sensitive {
            ser.append_pair(&k, "[redacted]");
        } else {
            ser.append_pair(&k, &v);
        }
    }
    ser.finish().into_bytes()
}

/// Walk a JSON Value recursively, replacing any object key whose name matches
/// (case-insensitively) one of `paths` with the string `[redacted]`.
pub fn redact_body_paths(value: &mut Value, paths: &[String]) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if paths.iter().any(|p| p.eq_ignore_ascii_case(k)) {
                    *v = Value::String("[redacted]".into());
                } else {
                    redact_body_paths(v, paths);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_body_paths(v, paths);
            }
        }
        _ => {}
    }
}

/// Like [`redact_body_paths`] but also always redacts the built-in
/// [`ALWAYS_SENSITIVE_FORM_KEYS`] (password, token, secret, access_token, …)
/// so credentials inside a recorded JSON body never persist in the clear.
pub fn redact_body_paths_defaulted(value: &mut Value, extra: &[String]) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let sensitive = ALWAYS_SENSITIVE_FORM_KEYS
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(k))
                    || extra.iter().any(|p| p.eq_ignore_ascii_case(k));
                if sensitive {
                    *v = Value::String("[redacted]".into());
                } else {
                    redact_body_paths_defaulted(v, extra);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_body_paths_defaulted(v, extra);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn header_match_is_case_insensitive() {
        let mut headers = vec![
            ("Authorization".into(), "Bearer xyz".into()),
            ("X-Trace-Id".into(), "abc123".into()),
        ];
        redact_headers(&mut headers, &["authorization".into()]);
        assert_eq!(headers[0].1, "[redacted]");
        assert_eq!(headers[1].1, "abc123");
    }

    #[test]
    fn header_no_match_left_alone() {
        let mut headers = vec![("Accept".into(), "application/json".into())];
        redact_headers(&mut headers, &["authorization".into()]);
        assert_eq!(headers[0].1, "application/json");
    }

    #[test]
    fn nested_json_key_match() {
        let mut v = json!({
            "user": {
                "name": "alice",
                "credentials": {
                    "password": "hunter2",
                    "token": "t-1"
                }
            },
            "meta": [
                { "Password": "another" },
                { "ok": true }
            ]
        });
        redact_body_paths(&mut v, &["password".into()]);
        assert_eq!(v["user"]["credentials"]["password"], json!("[redacted]"));
        assert_eq!(v["user"]["credentials"]["token"], json!("t-1"));
        assert_eq!(v["meta"][0]["Password"], json!("[redacted]"));
        assert_eq!(v["meta"][1]["ok"], json!(true));
        assert_eq!(v["user"]["name"], json!("alice"));
    }

    #[test]
    fn non_matching_keys_untouched() {
        let original = json!({"a": 1, "b": [1,2,3], "c": {"d": "e"}});
        let mut v = original.clone();
        redact_body_paths(&mut v, &["password".into()]);
        assert_eq!(v, original);
    }

    #[test]
    fn defaulted_headers_redact_credentials_without_config() {
        let mut headers = vec![
            ("Authorization".into(), "Bearer xyz".into()),
            ("Set-Cookie".into(), "sess=abc".into()),
            ("Accept".into(), "application/json".into()),
        ];
        redact_headers_defaulted(&mut headers, &[]);
        assert_eq!(headers[0].1, "[redacted]");
        assert_eq!(headers[1].1, "[redacted]");
        assert_eq!(headers[2].1, "application/json");
    }

    #[test]
    fn form_body_redacts_sensitive_values() {
        let body = b"username=alice&password=hunter2&grant_type=password";
        let out = redact_form_urlencoded(body, &[]);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("username=alice"));
        assert!(s.contains("password=%5Bredacted%5D"), "got: {s}");
        assert!(s.contains("grant_type=password"));
    }

    #[test]
    fn form_body_non_utf8_unchanged() {
        let body = &[0xff, 0xfe, 0x00, 0x01][..];
        assert_eq!(redact_form_urlencoded(body, &[]), body.to_vec());
    }
}
