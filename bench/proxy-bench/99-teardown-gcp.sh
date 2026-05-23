#!/usr/bin/env bash
# Delete the GCE VMs + firewall rules + subnet + VPC created by
# 00-provision-gcp.sh. Confined to the names in .env — won't touch
# anything else in the project.

set -euo pipefail
cd "$(dirname "$0")"
source .env

PROJECT="${GCP_PROJECT:?GCP_PROJECT must be set}"
ZONE="${GCP_ZONE:?GCP_ZONE must be set}"
REGION="${ZONE%-*}"

echo "About to DELETE in project $PROJECT:"
echo "  Instances: $SUT_NAME, $CLIENT_NAME (zone $ZONE)"
echo "  Firewall:  ${GCP_NETWORK}-allow-ssh, ${GCP_NETWORK}-allow-intra"
echo "  Subnet:    $GCP_SUBNET (region $REGION)"
echo "  Network:   $GCP_NETWORK"
read -r -p "Type 'yes' to confirm: " CONFIRM
[[ "$CONFIRM" == "yes" ]] || { echo "aborted"; exit 1; }

GCLOUD="gcloud --project=$PROJECT --quiet"

# Instances are deleted first; that releases the subnet binding so we
# can later delete the subnet + VPC cleanly. `|| true` after each so
# a missing resource doesn't abort the rest of the teardown.
echo "==> deleting instances"
$GCLOUD compute instances delete "$SUT_NAME" "$CLIENT_NAME" --zone "$ZONE" || true

echo "==> deleting firewall rules"
$GCLOUD compute firewall-rules delete \
  "${GCP_NETWORK}-allow-ssh" "${GCP_NETWORK}-allow-intra" || true

echo "==> deleting subnet"
$GCLOUD compute networks subnets delete "$GCP_SUBNET" --region "$REGION" || true

echo "==> deleting VPC"
$GCLOUD compute networks delete "$GCP_NETWORK" || true

rm -f .ips
echo "Done."
