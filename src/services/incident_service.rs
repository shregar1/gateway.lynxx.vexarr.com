use crate::db::Repository;
use crate::error::GatewayError;
use crate::models::{Incident, IncidentUpdate};
use std::sync::Arc;
use uuid::Uuid;

pub struct IncidentService {
    repo: Arc<dyn Repository>,
}

impl IncidentService {
    pub fn new(repo: Arc<dyn Repository>) -> Self {
        Self { repo }
    }

    pub async fn list(&self, service_id: &Uuid) -> Result<Vec<Incident>, GatewayError> {
        self.repo.list_incidents(service_id).await
    }

    pub async fn get(&self, id: &Uuid) -> Result<Option<Incident>, GatewayError> {
        self.repo.get_incident(id).await
    }

    pub async fn create(&self, incident: &Incident) -> Result<(), GatewayError> {
        self.repo.create_incident(incident).await
    }

    pub async fn update(&self, id: &Uuid, incident: &Incident) -> Result<(), GatewayError> {
        self.repo.update_incident(id, incident).await
    }

    pub async fn delete(&self, id: &Uuid) -> Result<bool, GatewayError> {
        self.repo.delete_incident(id).await
    }

    pub async fn list_updates(
        &self,
        incident_id: &Uuid,
    ) -> Result<Vec<IncidentUpdate>, GatewayError> {
        self.repo.list_incident_updates(incident_id).await
    }

    pub async fn create_update(&self, update: &IncidentUpdate) -> Result<(), GatewayError> {
        self.repo.create_incident_update(update).await
    }
}

impl crate::abstractions::IService for IncidentService {
    fn repo(&self) -> &Arc<dyn Repository> {
        &self.repo
    }
}
