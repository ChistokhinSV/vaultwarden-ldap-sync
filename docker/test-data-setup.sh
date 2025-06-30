#!/bin/bash
# Test data setup script for enhanced LDAP test scenarios

set -e

LDAP_HOST="${LDAP_HOST:-ldap://localhost:3389}"
BIND_DN="${LDAP_BIND_DN:-cn=Directory Manager}"
BIND_PASSWORD="${LDAP_BIND_PASSWORD:-adminpassword}"
BASE_DN="${LDAP_BASE_DN:-dc=domain,dc=local}"

echo "Setting up enhanced LDAP test data..."

# Create LDIF file for additional test data
cat > /tmp/enhanced-test-data.ldif << 'EOF'
# Additional groups for multi-org testing
dn: cn=vaultwarden-org1,cn=groups,cn=accounts,dc=domain,dc=local
objectClass: top
objectClass: groupOfUniqueNames
cn: vaultwarden-org1
description: VaultWarden Organization 1 Users
uniqueMember: uid=user,cn=users,cn=accounts,dc=domain,dc=local
uniqueMember: uid=user2,cn=users,cn=accounts,dc=domain,dc=local

dn: cn=vaultwarden-org2,cn=groups,cn=accounts,dc=domain,dc=local
objectClass: top
objectClass: groupOfUniqueNames
cn: vaultwarden-org2
description: VaultWarden Organization 2 Users
uniqueMember: uid=user3,cn=users,cn=accounts,dc=domain,dc=local
uniqueMember: uid=user4,cn=users,cn=accounts,dc=domain,dc=local

# Additional test users for privilege testing
dn: uid=admin_user,cn=users,cn=accounts,dc=domain,dc=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: admin_user
cn: Admin User
sn: User
givenName: Admin
mail: admin@domain.local
userPassword: {SSHA}VaultWarden123!

dn: uid=limited_user,cn=users,cn=accounts,dc=domain,dc=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: limited_user
cn: Limited User
sn: User
givenName: Limited
mail: limited@domain.local
userPassword: {SSHA}VaultWarden123!
nsAccountLock: true

# Additional test group for privilege testing
dn: cn=vaultwarden-admins,cn=groups,cn=accounts,dc=domain,dc=local
objectClass: top
objectClass: groupOfUniqueNames
cn: vaultwarden-admins
description: VaultWarden Admin Users
uniqueMember: uid=admin_user,cn=users,cn=accounts,dc=domain,dc=local

# Test group with mixed user statuses
dn: cn=vaultwarden-mixed,cn=groups,cn=accounts,dc=domain,dc=local
objectClass: top
objectClass: groupOfUniqueNames
cn: vaultwarden-mixed
description: Mixed status users for testing
uniqueMember: uid=user,cn=users,cn=accounts,dc=domain,dc=local
uniqueMember: uid=limited_user,cn=users,cn=accounts,dc=domain,dc=local
uniqueMember: uid=user4,cn=users,cn=accounts,dc=domain,dc=local
EOF

# Wait for LDAP server to be ready
echo "Waiting for LDAP server..."
timeout 60 bash -c "until ldapsearch -x -H '$LDAP_HOST' -D '$BIND_DN' -w '$BIND_PASSWORD' -b '$BASE_DN' '(objectClass=*)' dn >/dev/null 2>&1; do sleep 2; done"

# Add the enhanced test data
echo "Adding enhanced test data to LDAP..."
ldapadd -x -H "$LDAP_HOST" -D "$BIND_DN" -w "$BIND_PASSWORD" -f /tmp/enhanced-test-data.ldif

echo "Enhanced LDAP test data setup complete!"

# Verify the data was added
echo "Verifying test data..."
echo "Groups:"
ldapsearch -x -H "$LDAP_HOST" -D "$BIND_DN" -w "$BIND_PASSWORD" -b "cn=groups,cn=accounts,$BASE_DN" "(objectClass=groupOfUniqueNames)" cn

echo "Additional users:"
ldapsearch -x -H "$LDAP_HOST" -D "$BIND_DN" -w "$BIND_PASSWORD" -b "cn=users,cn=accounts,$BASE_DN" "(|(uid=admin_user)(uid=limited_user))" uid mail nsAccountLock

# Clean up
rm -f /tmp/enhanced-test-data.ldif