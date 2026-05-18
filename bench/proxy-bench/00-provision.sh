#!/usr/bin/env bash
# Provision 2 Azure VMs in the same proximity placement group: SUT + Client.
# Idempotent — re-running on an existing RG no-ops where possible.
set -euo pipefail
cd "$(dirname "$0")"
source .env

if [[ ! -f "${SSH_PUBKEY/#\~/$HOME}" ]]; then
  echo "ERROR: SSH pubkey not found at $SSH_PUBKEY"; exit 1
fi
PUBKEY_VAL="$(cat "${SSH_PUBKEY/#\~/$HOME}")"

echo "==> [1/7] Resource group $AZ_RG in $AZ_LOCATION"
az group create -n "$AZ_RG" -l "$AZ_LOCATION" -o none

echo "==> [2/7] Proximity placement group (optional — empty AZ_PPG to skip)"
if [[ -n "${AZ_PPG:-}" ]]; then
  az ppg create -n "$AZ_PPG" -g "$AZ_RG" -l "$AZ_LOCATION" -o none 2>/dev/null || true
fi

echo "==> [3/7] VNet + Subnet"
az network vnet create -g "$AZ_RG" -n "$AZ_VNET" --address-prefix 10.50.0.0/16 \
  --subnet-name "$AZ_SUBNET" --subnet-prefix 10.50.1.0/24 -o none

echo "==> [4/7] NSG (SSH from anywhere + intra-VNet on 28080-28099, 19090)"
az network nsg create -g "$AZ_RG" -n "$AZ_NSG" -o none
az network nsg rule create -g "$AZ_RG" --nsg-name "$AZ_NSG" -n allow-ssh \
  --priority 1000 --source-address-prefixes '*' --destination-port-ranges 22 \
  --access Allow --protocol Tcp -o none 2>/dev/null || true
az network nsg rule create -g "$AZ_RG" --nsg-name "$AZ_NSG" -n allow-intravnet \
  --priority 1100 --source-address-prefixes 10.50.0.0/16 --destination-port-ranges '*' \
  --access Allow --protocol '*' -o none 2>/dev/null || true
az network vnet subnet update -g "$AZ_RG" --vnet-name "$AZ_VNET" -n "$AZ_SUBNET" \
  --network-security-group "$AZ_NSG" -o none

create_vm () {
  local name="$1"; shift
  local sizes=("$@")   # fallback chain
  if az vm show -g "$AZ_RG" -n "$name" -o none 2>/dev/null; then
    echo "    (already exists, skipping)"; return 0
  fi
  local ppg_arg=()
  [[ -n "${AZ_PPG:-}" ]] && ppg_arg=(--ppg "$AZ_PPG")
  for size in "${sizes[@]}"; do
    echo "    trying size: $size"
    if az vm create -g "$AZ_RG" -n "$name" \
        --image "$AZ_IMAGE" --size "$size" \
        --admin-username "$ADMIN_USER" --ssh-key-values "$PUBKEY_VAL" \
        --vnet-name "$AZ_VNET" --subnet "$AZ_SUBNET" \
        --nsg "" --public-ip-sku Standard ${ppg_arg[@]+"${ppg_arg[@]}"} \
        --accelerated-networking true \
        --os-disk-size-gb 128 \
        -o none 2>/tmp/az_err_$$; then
      echo "    ✓ created $name as $size"
      echo "$name=$size" >> .sizes-used
      return 0
    fi
    if grep -q "SkuNotAvailable" /tmp/az_err_$$ 2>/dev/null; then
      echo "    capacity-blocked on $size, trying next..."
      continue
    fi
    cat /tmp/az_err_$$
    return 1
  done
  echo "ERROR: all sizes failed for $name"; return 1
}

# Fallback SKU chains (eat-the-first-available). All fit in 65 vCPU per-family quota.
SUT_SIZES=(${SUT_SIZES_FALLBACK:-$SUT_SIZE Standard_F32s_v2 Standard_D16s_v5 Standard_F16s_v2 Standard_D8s_v5})
CLIENT_SIZES=(${CLIENT_SIZES_FALLBACK:-$CLIENT_SIZE Standard_F32s_v2 Standard_D16s_v5 Standard_F16s_v2 Standard_D8s_v5})

echo "==> [5/7] SUT VM ($SUT_NAME, fallback chain: ${SUT_SIZES[*]})"
create_vm "$SUT_NAME" "${SUT_SIZES[@]}" || exit 1

echo "==> [6/7] Client VM ($CLIENT_NAME, fallback chain: ${CLIENT_SIZES[*]})"
create_vm "$CLIENT_NAME" "${CLIENT_SIZES[@]}" || exit 1

echo "==> [7/7] Auto-shutdown at 23:00 local time (failsafe against \$300 overnight mistakes)"
for vm in "$SUT_NAME" "$CLIENT_NAME"; do
  az vm auto-shutdown -g "$AZ_RG" -n "$vm" --time 2300 -o none 2>/dev/null || true
done

SUT_IP=$(az vm show -g "$AZ_RG" -n "$SUT_NAME" -d --query publicIps -o tsv)
CLIENT_IP=$(az vm show -g "$AZ_RG" -n "$CLIENT_NAME" -d --query publicIps -o tsv)
SUT_PRIV=$(az vm show -g "$AZ_RG" -n "$SUT_NAME" -d --query privateIps -o tsv)
CLIENT_PRIV=$(az vm show -g "$AZ_RG" -n "$CLIENT_NAME" -d --query privateIps -o tsv)

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
echo "  ssh $ADMIN_USER@$SUT_IP"
echo "  ssh $ADMIN_USER@$CLIENT_IP"
echo "================================================================"
