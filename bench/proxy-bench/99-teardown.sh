#!/usr/bin/env bash
# Nuke the whole resource group. Safe — confined to AZ_RG, won't touch anything else.
set -euo pipefail
cd "$(dirname "$0")"
source .env

echo "About to DELETE resource group: $AZ_RG"
echo "  (this destroys both VMs, all disks, the VNet — everything created by 00-provision.sh)"
read -r -p "Type the RG name to confirm: " CONFIRM
[[ "$CONFIRM" == "$AZ_RG" ]] || { echo "aborted"; exit 1; }

az group delete -n "$AZ_RG" --yes --no-wait
echo "Delete kicked off (async). Run 'az group show -n $AZ_RG' to check progress."
rm -f .ips
