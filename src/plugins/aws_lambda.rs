use crate::error::{GatewayError, PluginError};
use crate::plugins::{BoxBody, Plugin};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response};
use base64::Engine;
use serde_json::Value;
use std::time::Duration;

pub struct AwsLambdaPlugin {
    pub function_name: String,
    pub region: String,
    pub client: reqwest::Client,
}

impl AwsLambdaPlugin {
    pub fn from_config(cfg: &serde_json::Value) -> Result<Self, GatewayError> {
        let function_name = cfg
            .get("function_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::ConfigError("missing function_name".to_string()))?
            .to_string();
        let region = cfg
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1")
            .to_string();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| GatewayError::Internal(format!("lambda client build: {e}")))?;

        Ok(Self {
            function_name,
            region,
            client,
        })
    }
}

#[async_trait]
impl Plugin for AwsLambdaPlugin {
    fn name(&self) -> &str {
        "aws-lambda"
    }

    async fn on_request(&self, req: &mut Request<Body>) -> Result<(), PluginError> {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        use http_body_util::BodyExt;
        let body = std::mem::replace(req.body_mut(), Body::empty());
        let collected = body
            .collect()
            .await
            .map_err(|e| PluginError::Internal(format!("lambda read body: {e}")))?
            .to_bytes();

        let body_b64 = base64::engine::general_purpose::STANDARD.encode(&collected);

        let event = serde_json::json!({
            "httpMethod": method,
            "path": path,
            "headers": headers
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect::<serde_json::Map<String, Value>>(),
            "body": body_b64,
            "isBase64Encoded": true,
        });

        // In a real implementation we would sign this with AWS credentials.
        // For this demo we just POST to a mock endpoint or assume a pre-signed URL.
        let url = format!(
            "https://lambda.{}.amazonaws.com/2015-03-31/functions/{}/invocations",
            self.region, self.function_name
        );

        let resp = self
            .client
            .post(url)
            .json(&event)
            .send()
            .await
            .map_err(|e| PluginError::Internal(format!("lambda invoke: {e}")))?;

        let status = resp.status().as_u16();
        let body_blob = resp
            .bytes()
            .await
            .map_err(|e| PluginError::Internal(format!("lambda read resp: {e}")))?
            .to_vec();

        let (status_u16, headers_out, body_out) = {
            let parsed: Value = serde_json::from_slice(&body_blob).unwrap_or(Value::Null);
            if let Some(obj) = parsed.as_object() {
                let s = obj
                    .get("statusCode")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u16)
                    .unwrap_or(200);
                let b_str = obj.get("body").and_then(|v| v.as_str()).unwrap_or("");
                let is_b64 = obj
                    .get("isBase64Encoded")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let b = if is_b64 {
                    base64::engine::general_purpose::STANDARD
                        .decode(b_str)
                        .unwrap_or_default()
                } else {
                    b_str.as_bytes().to_vec()
                };
                let mut hdrs = Vec::new();
                if let Some(h_obj) = obj.get("headers").and_then(|v| v.as_object()) {
                    for (k, val) in h_obj {
                        if let Some(s) = val.as_str() {
                            hdrs.push((k.clone(), s.to_string()));
                        }
                    }
                }
                (s, hdrs, b)
            } else {
                (
                    if status == 0 { 200 } else { status },
                    vec![("Content-Type".to_string(), "application/json".to_string())],
                    body_blob,
                )
            }
        };

        return Err(PluginError::ShortCircuit {
            status: status_u16,
            headers: headers_out,
            body: body_out.into(),
        });
    }

    async fn on_response(&self, _resp: &mut Response<BoxBody>) -> Result<(), PluginError> {
        Ok(())
    }
}
