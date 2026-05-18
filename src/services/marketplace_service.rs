use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::MarketplacePlugin;
use std::sync::Arc;
use uuid::Uuid;

pub struct MarketplaceService {
    repo: Arc<dyn Repository>,
}

impl MarketplaceService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list(&self) -> Result<Vec<MarketplacePlugin>, GatewayError> {
        self.repo.list_marketplace_plugins().await
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<MarketplacePlugin>, GatewayError> {
        self.repo.get_marketplace_plugin(id).await
    }

    pub async fn create(&self, plugin: &MarketplacePlugin) -> Result<(), GatewayError> {
        self.repo.create_marketplace_plugin(plugin).await
    }

    pub async fn update(&self, id: &Uuid, plugin: &MarketplacePlugin) -> Result<(), GatewayError> {
        self.repo.update_marketplace_plugin(id, plugin).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool, GatewayError> {
        self.repo.delete_marketplace_plugin(id).await
    }
}

impl crate::abstractions::IService for MarketplaceService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
