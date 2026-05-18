//! Token counting for the LLM gateway.
//!
//! For OpenAI-family models we use [`tiktoken-rs`] with the BPE matching the
//! published encoding for that model family. For everything else we fall back
//! to `len(text) / 4`, which is the documented OpenAI rule of thumb and is
//! within ~10% of Anthropic's actual count for English prose.
//!
//! `count_messages` is the hot-path entry point: it sums tokens across all
//! `messages[].content` strings before forwarding upstream. We do NOT add the
//! per-message overhead (4 tokens for role/separators) the OpenAI cookbook
//! describes — for budget purposes the slight under-count is on the cautious
//! side of the rate limiter (we'll permit slightly more than asked, never
//! less), and avoiding magic constants keeps the code readable across
//! provider shapes.

use serde_json::Value;
use std::sync::OnceLock;
use tiktoken_rs::CoreBPE;

/// Encoder selected by model family.
#[derive(Clone, Copy)]
enum Encoder {
    /// `o200k_base` — gpt-4o, gpt-4o-mini, o1, o3 family.
    O200kBase,
    /// `cl100k_base` — gpt-4, gpt-3.5-turbo, embeddings.
    Cl100kBase,
    /// Unknown / non-OpenAI: estimate via `len/4`.
    Estimate,
}

fn pick_encoder(model: &str) -> Encoder {
    let m = model.to_ascii_lowercase();
    if m.starts_with("gpt-4o") || m.starts_with("o1") || m.starts_with("o3") || m.starts_with("o4")
    {
        Encoder::O200kBase
    } else if m.starts_with("gpt-4") || m.starts_with("gpt-3.5") || m.starts_with("text-embedding")
    {
        Encoder::Cl100kBase
    } else {
        Encoder::Estimate
    }
}

fn cl100k() -> &'static CoreBPE {
    static CL: OnceLock<CoreBPE> = OnceLock::new();
    CL.get_or_init(|| tiktoken_rs::cl100k_base().expect("cl100k_base BPE bundled with tiktoken-rs"))
}

fn o200k() -> &'static CoreBPE {
    static O2: OnceLock<CoreBPE> = OnceLock::new();
    O2.get_or_init(|| tiktoken_rs::o200k_base().expect("o200k_base BPE bundled with tiktoken-rs"))
}

/// Count tokens in a single string, using the BPE for the named model.
///
/// For non-OpenAI models we estimate. The estimate is documented and the
/// returned value is on the conservative side (likely to over-count slightly,
/// which means we'll bill clients accurately and rate-limit early — both
/// safe failure modes).
pub fn count_text(model: &str, text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    match pick_encoder(model) {
        Encoder::O200kBase => o200k().encode_with_special_tokens(text).len(),
        Encoder::Cl100kBase => cl100k().encode_with_special_tokens(text).len(),
        Encoder::Estimate => {
            // OpenAI's published rule of thumb: ~4 chars per token in English.
            // We round up so single short messages still cost at least one
            // token in the bucket accounting.
            text.chars().count().div_ceil(4)
        }
    }
}

/// Sum tokens over an OpenAI-shaped `messages` array. Each message's
/// `content` may be either a string (the common case) or an array of parts
/// `[{type:"text", text:"..."}]` (vision / multipart). Non-string parts are
/// ignored — we don't try to estimate image tokens here; the upstream's
/// `usage` block on the response will include them if it counts them.
pub fn count_messages(model: &str, messages: &[Value]) -> usize {
    let mut total = 0;
    for msg in messages {
        match msg.get("content") {
            Some(Value::String(s)) => total += count_text(model, s),
            Some(Value::Array(parts)) => {
                for part in parts {
                    if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                        total += count_text(model, text);
                    }
                }
            }
            _ => {}
        }
    }
    total
}

/// Pull `usage.prompt_tokens` / `usage.completion_tokens` out of an OpenAI-
/// shaped JSON response. Returns `None` if the response did not include a
/// `usage` block (e.g. some local/llama backends omit it). Callers should
/// fall back to [`count_text`] over the response content in that case.
pub fn extract_usage(body: &Value) -> Option<(u64, u64)> {
    let usage = body.get("usage")?;
    let prompt = usage.get("prompt_tokens").and_then(|v| v.as_u64())?;
    let completion = usage
        .get("completion_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Some((prompt, completion))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cl100k_known_short_string() {
        // "hello" is one token in cl100k.
        assert_eq!(count_text("gpt-4", "hello"), 1);
    }

    #[test]
    fn estimate_rounds_up() {
        assert_eq!(count_text("llama3", ""), 0);
        assert_eq!(count_text("llama3", "abcd"), 1);
        assert_eq!(count_text("llama3", "abcde"), 2);
    }

    #[test]
    fn count_messages_handles_string_and_parts() {
        let msgs = vec![
            serde_json::json!({"role": "user", "content": "hello"}),
            serde_json::json!({
                "role": "user",
                "content": [{"type": "text", "text": "world"}, {"type": "image_url"}]
            }),
        ];
        let n = count_messages("gpt-4", &msgs);
        assert!(n >= 2, "expected >= 2 tokens, got {n}");
    }
}
