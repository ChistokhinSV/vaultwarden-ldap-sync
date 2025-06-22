#!/bin/bash

## Now add some entries
echo "Adding Users user, user2, user3"
ldapadd -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x <<EOF
dn: uid=user,cn=users,cn=accounts,${DS_SUFFIX_NAME}
uid: user
givenName: User
objectClass: inetorgperson
objectClass: inetuser
sn: User
cn: User
userPassword: {CLEARTEXT}vaultwarden
EOF

echo "Adding User user2"
ldapadd -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x <<EOF
dn: uid=user2,cn=users,cn=accounts,${DS_SUFFIX_NAME}
uid: user2
givenName: User2
objectClass: inetorgperson
objectClass: inetuser
sn: User2
cn: User2
userPassword: {CLEARTEXT}vaultwarden
EOF

echo "Adding User user3"
ldapadd -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x <<EOF
dn: uid=user3,cn=users,cn=accounts,${DS_SUFFIX_NAME}
uid: user3
givenName: User3
objectClass: inetorgperson
objectClass: inetuser
sn: User3
cn: User3
userPassword: {CLEARTEXT}vaultwarden
EOF

echo "Adding Group vaultwarden-users"
ldapadd -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x <<EOF
dn: cn=vaultwarden-users,cn=groups,cn=accounts,${DS_SUFFIX_NAME}
cn: vaultwarden-users
objectclass: groupOfNames

EOF

echo "Adding users user, user2 to group vaultwarden-users"
ldapmodify -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x <<EOF
dn: cn=vaultwarden-users,cn=groups,cn=accounts,${DS_SUFFIX_NAME}
changetype: modify
add: member
member: uid=user,cn=users,cn=accounts,${DS_SUFFIX_NAME}
member: uid=user2,cn=users,cn=accounts,${DS_SUFFIX_NAME}
EOF
