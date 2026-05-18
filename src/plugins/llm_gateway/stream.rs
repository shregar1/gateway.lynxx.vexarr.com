//! SSE (Server-Sent Events) helpers for streaming LLM responses.
//!
//! v1 streaming approach: when the upstream returns
//! `Content-Type: text/event-stream` we forward the body bytes to the client
//! verbatim and parse a *copy* synchronously to count completion tokens.
//! Because the proxy hot path materialises the full response body before the
//! `on_response` plugin chain runs (see `proxy/handler.rs`), our streaming
//! support is "all-at-once" in the gateway: the upstream stream is consumed
//! in full, then the response is replayed to the client. This matches the
//! existing architectural contract; a future optimisation could re-thread
//! true incremental forwarding, but every commercial gateway today (Kong AI
//! Gateway, Portkey, Helicone) does the same thing for the sake of policy
//! evaluation.
//!
//! The parser walks `data: {...}\n\n` frames and extracts:
//! - OpenAI shape: `choices[].delta.content` (string)
//! - Anthropic shape: `delta.text` for `content_block_delta` events
//! - Final `[DONE]` sentinel, ignored
//!
//! Tokens are counted via [`super::tokens::count_text`] using the request's
//! model id.

use super::tokens;
use crate::plugins::llm_gateway::buckets::Buckets;
use bytes::Bytes;
use futures_util::Stream;
use serde_json::Value;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Output of stream-body analysis.
#[derive(Debug, Clone, Default)]
pub struct StreamUsage {
    pub completion_tokens: u64,
    /// Some upstreams (OpenAI when `stream_options: {include_usage: true}`)
    /// emit a final `usage` block — we prefer it over our own count when
    /// available.
    pub upstream_prompt_tokens: Option<u64>,
    pub upstream_completion_tokens: Option<u64>,
}

/// A wrapper stream that counts LLM tokens on-the-fly as SSE frames pass through.
/// When the stream ends (or is dropped), it can optionally report usage back
/// to the rate-limiter for post-hoc quota adjustment.
pub struct TokenCountingStream<S> {
    inner: S,
    model: String,
    buffer: Vec<u8>,
    usage: StreamUsage,
    consumer: String,
    buckets: Arc<Buckets>,
    initial_estimate: u64,
}

impl<S> TokenCountingStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
{
    pub fn new(
        inner: S,
        model: String,
        consumer: String,
        buckets: Arc<Buckets>,
        initial_estimate: u64,
    ) -> Self {
        Self {
            inner,
            model,
            buffer: Vec::new(),
            usage: StreamUsage::default(),
            consumer,
            buckets,
            initial_estimate,
        }
    }

    fn process_buffer(&mut self) {
        // SSE frames are separated by \n\n. We search for complete frames
        // in our buffer, parse them, and update the token count.
        let mut pos = 0;
        while let Some(rel_pos) = self.buffer[pos..].windows(2).position(|w| w == b"\n\n") {
            let frame_end = pos + rel_pos;
            let frame = self.buffer[pos..frame_end].to_vec();
            self.analyze_frame(&frame);
            pos = frame_end + 2;
        }
        if pos > 0 {
            self.buffer.drain(0..pos);
        }
    }

    fn analyze_frame(&mut self, frame: &[u8]) {
        accumulate_sse_frame(&self.model, frame, &mut self.usage);
    }
}

/// Apply one SSE `data:` frame to token / usage counters (shared by stream
/// parser and tests).
fn accumulate_sse_frame(model: &str, frame: &[u8], usage: &mut StreamUsage) {
    let s = std::str::from_utf8(frame).unwrap_or("");
    for line in s.lines() {
        let line = line.trim();
        let Some(payload) = line
            .strip_prefix("data: ")
            .or_else(|| line.strip_prefix("data:"))
        else {
            continue;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(payload) else {
            continue;
        };

        // OpenAI streaming: choices[].delta.content
        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            for ch in choices {
                if let Some(delta) = ch.get("delta") {
                    if let Some(text) = delta.get("content").and_then(|t| t.as_str()) {
                        usage.completion_tokens += tokens::count_text(model, text) as u64;
                    }
                }
            }
        }

        // Anthropic streaming: type=="content_block_delta" with delta.text
        if v.get("type").and_then(|t| t.as_str()) == Some("content_block_delta") {
            if let Some(text) = v
                .get("delta")
                .and_then(|d| d.get("text"))
                .and_then(|t| t.as_str())
            {
                usage.completion_tokens += tokens::count_text(model, text) as u64;
            }
        }

        // Final usage block
        if let Some(u) = v
            .get("usage")
            .or_else(|| v.get("message").and_then(|m| m.get("usage")))
        {
            if let Some(p) = u
                .get("prompt_tokens")
                .or_else(|| u.get("input_tokens"))
                .and_then(|x| x.as_u64())
            {
                usage.upstream_prompt_tokens = Some(p);
            }
            if let Some(c) = u
                .get("completion_tokens")
                .or_else(|| u.get("output_tokens"))
                .and_then(|x| x.as_u64())
            {
                usage.upstream_completion_tokens = Some(c);
            }
        }
    }
}

#[cfg(test)]
fn analyze_sse_body(model: &str, body: &[u8]) -> StreamUsage {
    let mut usage = StreamUsage::default();
    let mut pos = 0;
    while let Some(rel_pos) = body[pos..].windows(2).position(|w| w == b"\n\n") {
        let frame_end = pos + rel_pos;
        accumulate_sse_frame(model, &body[pos..frame_end], &mut usage);
        pos = frame_end + 2;
    }
    if pos < body.len() {
        accumulate_sse_frame(model, &body[pos..], &mut usage);
    }
    usage
}

impl<S> Stream for TokenCountingStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
{
    type Item = Result<Bytes, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.buffer.extend_from_slice(&bytes);
                self.process_buffer();
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(axum::Error::new(e)))),
            Poll::Ready(None) => {
                // Final flush of any remaining buffer.
                let frame = std::mem::take(&mut self.buffer);
                if !frame.is_empty() {
                    self.analyze_frame(&frame);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> Drop for TokenCountingStream<S> {
    fn drop(&mut self) {
        // Post-hoc quota adjustment.
        let actual_total = self
            .usage
            .upstream_completion_tokens
            .unwrap_or(self.usage.completion_tokens);
        // We only adjust if we have a non-zero count. If the stream was
        // interrupted before any tokens were parsed, we stick with the
        // initial estimate as a safety measure.
        if actual_total > 0 {
            let delta = (self.initial_estimate as i64) - (actual_total as i64);
            if delta != 0 {
                // If delta is positive, we over-estimated (refund).
                // If delta is negative, we under-estimated (charge more).
                // Note: initial_estimate included prompt tokens, so we should
                // really compare against (prompt + completion).
                // TODO: refine this to include actual prompt tokens from upstream usage block.
                self.buckets.refund(&self.consumer, delta);
            }
        }
    }
}

/// Detect "is this an SSE stream" by content-type.
pub fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type
        .map(|c| {
            c.trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_event_stream_content_type() {
        assert!(is_event_stream(Some("text/event-stream")));
        assert!(is_event_stream(Some("text/event-stream; charset=utf-8")));
        assert!(!is_event_stream(Some("application/json")));
        assert!(!is_event_stream(None));
    }

    #[test]
    fn counts_openai_stream_tokens() {
        let body = b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n\
                    data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n\
                    data: [DONE]\n\n";
        let u = analyze_sse_body("gpt-4o", body);
        assert!(u.completion_tokens >= 2);
    }

    #[test]
    fn counts_anthropic_stream_tokens() {
        let body = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n\
                    data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\" there\"}}\n\n";
        let u = analyze_sse_body("claude-3-5-sonnet-20240620", body);
        assert!(u.completion_tokens >= 1);
    }

    #[test]
    fn picks_up_upstream_usage_block() {
        let body =
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":13}}\n\n";
        let u = analyze_sse_body("gpt-4o", body);
        assert_eq!(u.upstream_prompt_tokens, Some(7));
        assert_eq!(u.upstream_completion_tokens, Some(13));
    }
}
