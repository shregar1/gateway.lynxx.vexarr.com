use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEnvelope<T: Serialize> {
    #[serde(rename = "transactionUrn")]
    pub transaction_urn: String,
    pub status: String,
    #[serde(rename = "responseMessage")]
    pub response_message: String,
    #[serde(rename = "responseKey")]
    pub response_key: String,
    pub errors: Vec<ApiErrorDetail>,
    pub timestamp: String,
    pub metadata: serde_json::Value,
    pub data: T,
    pub reference_urn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    pub code: String,
    pub message: String,
}

impl<T: Serialize> ApiEnvelope<T> {
    pub fn success(
        data: T,
        transaction_urn: String,
        timestamp: String,
        reference_urn: String,
    ) -> Self {
        Self {
            transaction_urn,
            status: "SUCCESS".into(),
            response_message: "Request processed successfully".into(),
            response_key: "SUCCESS".into(),
            errors: vec![],
            timestamp,
            metadata: serde_json::json!({}),
            data,
            reference_urn,
        }
    }
}

impl ApiEnvelope<serde_json::Value> {
    pub fn error(
        response_key: &str,
        message: &str,
        transaction_urn: String,
        timestamp: String,
        reference_urn: String,
    ) -> Self {
        Self {
            transaction_urn,
            status: "FAILED".into(),
            response_message: message.into(),
            response_key: response_key.into(),
            errors: vec![ApiErrorDetail {
                code: response_key.into(),
                message: message.into(),
            }],
            timestamp,
            metadata: serde_json::json!({}),
            data: serde_json::Value::Null,
            reference_urn,
        }
    }
}
