#!/bin/bash

# One-time initialization can run during image build to speed up future runs.
# This may be a terrible idea though: https://github.com/389ds/389-ds-base/issues/4620
echo "------------------------"
echo "| Step 1: Start dirsrv |"
echo "------------------------"

/usr/lib/dirsrv/dscontainer -r &

echo "------------------------------------"
echo "| Step 2: Wait for dirsrv to start |"
echo "------------------------------------"

# until ldapwhoami -H ldap://localhost:3389 -x | grep -q "anonymous";
# until dsctl --json slapd-localhost healthcheck | grep -q "[]";
until /usr/lib/dirsrv/dscontainer -H;
do
  echo $(date) " Still waiting for dirsrv to start..."
  sleep 5
done

# TODO: healthcheck above returns even if dirsrv isn't quite ready
# Note: the dscontainer -H healthcheck returns before the server is really ready for two reasons:
# 1. The Directory Manager password is set AFTER healthy is reported!
# 2. The connection tested is ldapi local pipe connection.   The socket connection may not be ready yet!
# The following error is the symptom:
# "ldap_bind: Invalid credentials (49)"
# During the Docker build we set the default test Directory Manager password, so unless you change it from the default
# the re-setting to same thing may not be a problem depending on how dirsrv behaves during set password transaction. To
# be safer best sleep a little.
# The local pipe vs port issue can be ameliorated by trying the port bind in a loop.
# See:
# - https://github.com/389ds/389-ds-base/pull/6070
# - https://github.com/389ds/389-ds-base/blob/d65eea90311543b3ea906cdc29ff526ae6b64956/src/lib389/cli/dscontainer#L389
# - https://github.com/389ds/389-ds-base/blob/d65eea90311543b3ea906cdc29ff526ae6b64956/src/lib389/cli/dscontainer#L402
until ldapwhoami -H ldap://localhost:3389 -x | grep -q "anonymous";
do
  echo $(date) " Still waiting for dirsrv to start (after Healthcheck says healthy)..."
  sleep 1
done
# Now sleep a minimize chance of encountering (but no guarantee) Directory Manager password change after healthy issue
sleep 10

echo "----------------------------------"
echo "| Step 3: Enable memberOf plugin |"
echo "----------------------------------"
## Enable memberOf plugin (requires dirsrv restart - using ldapi assuming root user)
ldapadd -Y EXTERNAL -H ldapi://%2fdata%2frun%2fslapd-localhost.socket <<EOF
dn: cn=MemberOf Plugin,cn=plugins,cn=config
changetype: modify
replace: nsslapd-pluginEnabled
nsslapd-pluginEnabled: on
EOF

echo "--------------------"
echo "| Step 4: Shutdown |"
echo "--------------------"
kill $(ps -ef | grep slapd-localhos[t] | tr -s " " | cut -d " " -f 2)

# Wait for server to actually handle SIGTERM signal
sleep 5
