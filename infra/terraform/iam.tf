# ---------------------------------------------------------------------------
# Service accounts + Workload Identity bindings.
#
# Gateway pods authenticate to Cloud SQL via Workload Identity (no static creds).
# GitHub Actions CI/CD authenticates via Workload Identity Federation (OIDC),
# removing the need for long-lived SA key files.
# ---------------------------------------------------------------------------

# ---- Gateway GCP service account ------------------------------------------

resource "google_service_account" "gateway" {
  account_id   = "lynxx-gateway"
  display_name = "Lynxx Gateway (GKE Workload Identity)"
}

resource "google_project_iam_member" "gateway_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

resource "google_project_iam_member" "gateway_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

# The Workload Identity pool (PROJECT.svc.id.goog) is created automatically
# when the GKE cluster is provisioned — we must wait for the cluster first.
resource "google_service_account_iam_member" "gateway_workload_identity" {
  service_account_id = google_service_account.gateway.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[lynxx-system/lynxx-gateway]"

  depends_on = [google_container_cluster.lynxx]
}

# ---- CI/CD GCP service account --------------------------------------------

resource "google_service_account" "cicd" {
  account_id   = "lynxx-cicd"
  display_name = "Lynxx CI/CD (GitHub Actions WIF)"
}

resource "google_project_iam_member" "cicd_ar_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_project_iam_member" "cicd_gke_developer" {
  project = var.project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_project_iam_member" "cicd_run_developer" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_project_iam_member" "cicd_sa_user" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

# ---- Workload Identity Federation — GitHub Actions OIDC -------------------
# Allows GitHub Actions workflows in this org to impersonate lynxx-cicd
# without any long-lived service account keys.

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "lynxx-github"
  display_name              = "GitHub Actions (Lynxx)"
  project                   = var.project_id

  depends_on = [google_project_service.apis["iam.googleapis.com"]]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub OIDC"
  project                            = var.project_id

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.actor"            = "assertion.actor"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
  }

  # Only allow workflows from the correct GitHub org/user.
  attribute_condition = "assertion.repository_owner == 'vexarr'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Allow any repo in the org to impersonate the CI/CD SA.
resource "google_service_account_iam_member" "cicd_wif" {
  service_account_id = google_service_account.cicd.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository_owner/vexarr"
}
