#!/bin/bash

# Remove empty key files from Azure IoT Identity Service key store
# and restart related services so IoT Edge can recover cleanly.

KEY_DIRS="/var/lib/aziot/keyd/keys /var/lib/aziot/certd/certs/"

for KEY_DIR in $KEY_DIRS; do
    if [[ -d "$KEY_DIR" ]]; then
        # Delete zero-byte key files
        find "$KEY_DIR" -type f -size 0 -print |xargs rm -rf
    fi
done
echo "Aziot empty key files removed (if any) and services restarted."

