#!/usr/bin/env bash
# Provision 2 GCE VMs in the same zone: SUT + Client. Idempotent —
# re-runs no-op if a VM / firewall / subnet already exists.
#
# Mirrors 00-provision.sh (Azure) but uses `gcloud compute` everywhere.
# Reads CLOUD=gcp + GCP_* vars from .env. The .ips file written at the
# end is in the SAME shape orchestrate.sh + deploy-lynxx.sh expect,
# so nothing else in the rig needs to know we're on GCP instead of
# Azure.

set -euo pipefail
cd "$(dirname "$0")"
source .env

[[ "${CLOUD:-}" == "gcp" ]] || { echo "ERROR: .env does not set CLOUD=gcp"; exit 1; }

PUBKEY_PATH="${SSH_PUBKEY/#\~/$HOME}"
[[ -f "$PUBKEY_PATH" ]] || { echo "ERROR: SSH pubkey not found at $PUBKEY_PATH"; exit 1; }
PUBKEY_VAL="$(cat "$PUBKEY_PATH")"

PROJECT="${GCP_PROJECT:?GCP_PROJECT must be set}"
ZONE="${GCP_ZONE:?GCP_ZONE must be set}"
REGION="${ZONE%-*}"
NETWORK="${GCP_NETWORK:?GCP_NETWORK must be set}"
SUBNET="${GCP_SUBNET:?GCP_SUBNET must be set}"

GCLOUD="gcloud --project=$PROJECT --quiet"

echo "==> [1/4] VPC ($NETWORK) + subnet ($SUBNET in $REGION)"
if ! $GCLOUD compute networks describe "$NETWORK" >/dev/null 2>&1; then
  $GCLOUD compute networks create "$NETWORK" --subnet-mode=custom
else
  echo "    (network exists, skipping)"
fi
if ! $GCLOUD compute networks subnets describe "$SUBNET" --region "$REGION" >/dev/null 2>&1; then
  $GCLOUD compute networks subnets create "$SUBNET" \
    --network "$NETWORK" --region "$REGION" --range "10.50.2.0/24"
else
  echo "    (subnet exists, skipping)"
fi

echo "==> [2/4] Firewall rules"
# allow-ssh: 22/tcp from anywhere — orchestrate.sh / deploy-lynxx.sh
# need this so the operator's laptop can ssh in.
if ! $GCLOUD compute firewall-rules describe "${NETWORK}-allow-ssh" >/dev/null 2>&1; then
  $GCLOUD compute firewall-rules create "${NETWORK}-allow-ssh" \
    --network "$NETWORK" --direction INGRESS --priority 1000 \
    --action ALLOW --rules tcp:22 --source-ranges 0.0.0.0/0
else
  echo "    (allow-ssh exists, skipping)"
fi
# allow-intra: all protocols within the bench subnet (Client → SUT
# on 28080 for the proxy hop, SUT → 19090 upstream loopback, etc.).
if ! $GCLOUD compute firewall-rules describe "${NETWORK}-allow-intra" >/dev/null 2>&1; then
  $GCLOUD compute firewall-rules create "${NETWORK}-allow-intra" \
    --network "$NETWORK" --direction INGRESS --priority 1100 \
    --action ALLOW --rules tcp,udp,icmp --source-ranges "10.50.0.0/16"
else
  echo "    (allow-intra exists, skipping)"
fi

create_vm () {
  local name="$1"
  local machine="$2"
  if $GCLOUD compute instances describe "$name" --zone "$ZONE" >/dev/null 2>&1; then
    echo "    (already exists, skipping)"
    return 0
  fi
  echo "    creating $name as $machine in $ZONE..."
  # IMAGE_FAMILY: ubuntu-2404-lts-amd64 (or whatever is set in .env).
  # The setup scripts assume Ubuntu 24.04 + apt; keep it consistent.
  #
  # Boot disk: 128 GB pd-ssd. Matches the Azure rig's --os-disk-size-gb 128.
  # pd-ssd because cargo build + docker image pull both spike disk I/O.
  #
  # Metadata ssh-keys: we install OUR pubkey, not OS Login. That lets
  # orchestrate.sh use plain ssh+scp (key-based) without going through
  # `gcloud compute ssh`'s tunnel. Much faster for high-frequency calls.
  $GCLOUD compute instances create "$name" \
    --zone "$ZONE" \
    --machine-type "$machine" \
    --network "$NETWORK" --subnet "$SUBNET" \
    --image-family "$GCP_IMAGE_FAMILY" --image-project "$GCP_IMAGE_PROJECT" \
    --boot-disk-size 128GB --boot-disk-type pd-ssd \
    --metadata "ssh-keys=$ADMIN_USER:$PUBKEY_VAL,enable-oslogin=FALSE" \
    --tags proxybench
}

echo "==> [3/4] SUT VM ($SUT_NAME, $SUT_MACHINE)"
create_vm "$SUT_NAME" "$SUT_MACHINE"

echo "==> [4/4] Client VM ($CLIENT_NAME, $CLIENT_MACHINE)"
create_vm "$CLIENT_NAME" "$CLIENT_MACHINE"

# IPs.
SUT_IP=$($GCLOUD compute instances describe "$SUT_NAME" --zone "$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
SUT_PRIV=$($GCLOUD compute instances describe "$SUT_NAME" --zone "$ZONE" \
  --format='get(networkInterfaces[0].networkIP)')
CLIENT_IP=$($GCLOUD compute instances describe "$CLIENT_NAME" --zone "$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
CLIENT_PRIV=$($GCLOUD compute instances describe "$CLIENT_NAME" --zone "$ZONE" \
  --format='get(networkInterfaces[0].networkIP)')

cat > .ips <<EOF
SUT_IP=$SUT_IP
SUT_PRIV=$SUT_PRIV
CLIENT_IP=$CLIENT_IP
CLIENT_PRIV=$CLIENT_PRIV
EOF

echo
echo "================================================================"
echo "Provisioned. IPs saved to .ips"
echo "  SUT:    $SUT_IP   (private $SUT_PRIV)"
echo "  Client: $CLIENT_IP   (private $CLIENT_PRIV)"
echo "  ssh -i ${PUBKEY_PATH%.pub} $ADMIN_USER@$SUT_IP"
echo "  ssh -i ${PUBKEY_PATH%.pub} $ADMIN_USER@$CLIENT_IP"
echo "================================================================"
