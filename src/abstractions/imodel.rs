use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

/// Base interface for all domain entities.
pub trait IModel: Send + Sync + Clone + std::fmt::Debug + Serialize + DeserializeOwned {
    fn id(&self) -> Uuid;
    fn created_at(&self) -> DateTime<Utc>;
    fn is_soft_deleted(&self) -> bool {
        false
    }
}
