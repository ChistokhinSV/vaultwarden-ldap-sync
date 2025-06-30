#!/bin/bash
# Enhanced entrypoint for 389ds test container with comprehensive test data

set -e

# Start the original entrypoint in background
/usr/local/bin/389ds.container-entrypoint.sh &
ENTRYPOINT_PID=$!

# Wait for 389ds to be fully ready
echo "Waiting for 389ds to be ready..."
timeout 120 bash -c 'until ldapsearch -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$DS_DM_PASSWORD" -b "$DS_SUFFIX_NAME" "(objectClass=*)" dn >/dev/null 2>&1; do sleep 2; done'

# Run the initial data setup
echo "Running initial test data setup..."
/opt/389ds_initdb.d/01_schema.sh
/opt/389ds_initdb.d/02_accounts.sh

# Run enhanced test data setup
echo "Running enhanced test data setup..."
/usr/local/bin/test-data-setup.sh

echo "Enhanced 389ds test container is ready!"

# Wait for the main process
wait $ENTRYPOINT_PID