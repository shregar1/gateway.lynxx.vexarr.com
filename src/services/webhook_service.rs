use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::{Webhook, WebhookDelivery};
use std::sync::Arc;
use uuid::Uuid;

pub struct WebhookService {
    repo: Arc<dyn Repository>,
}

impl WebhookService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list(&self, service_id: &Uuid) -> Result<Vec<Webhook>, GatewayError> {
        self.repo.list_webhooks(service_id).await
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<Webhook>, GatewayError> {
        self.repo.get_webhook(id).await
    }

    pub async fn create(&self, webhook: &Webhook) -> Result<(), GatewayError> {
        self.repo.create_webhook(webhook).await
    }

    pub async fn update(&self, id: &Uuid, webhook: &Webhook) -> Result<(), GatewayError> {
        self.repo.update_webhook(id, webhook).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool, GatewayError> {
        self.repo.delete_webhook(id).await
    }

    pub async fn list_deliveries(
        &self,
        webhook_id: &Uuid,
        limit: u32,
    ) -> Result<Vec<WebhookDelivery>, GatewayError> {
        self.repo.list_webhook_deliveries(webhook_id, limit).await
    }

    pub async fn create_delivery(&self, delivery: &WebhookDelivery) -> Result<(), GatewayError> {
        self.repo.create_webhook_delivery(delivery).await
    }
}

impl crate::abstractions::IService for WebhookService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
