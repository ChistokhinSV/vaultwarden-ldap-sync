#!/bin/bash

## Now add some entries

echo "Adding Group vaultwarden-users"
ldapadd -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x <<EOF
dn: cn=vaultwarden-users,cn=groups,cn=accounts,${DS_SUFFIX_NAME}
cn: vaultwarden-users
objectclass: groupOfNames
EOF

echo "Adding Users user, user2, user3, user4"
ldapadd -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x <<EOF
dn: uid=user,cn=users,cn=accounts,${DS_SUFFIX_NAME}
uid: user
givenName: User
objectClass: inetorgperson
objectClass: inetuser
sn: User
cn: User
mail: user@domain.local
userPassword: {CLEARTEXT}vaultwarden
memberOf: cn=vaultwarden-users,cn=groups,cn=accounts,${DS_SUFFIX_NAME}
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
mail: user2@domain.local
userPassword: {CLEARTEXT}vaultwarden
memberOf: cn=vaultwarden-users,cn=groups,cn=accounts,${DS_SUFFIX_NAME}
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
mail: user3@domain.local
userPassword: {CLEARTEXT}vaultwarden
EOF


echo "Adding User user4"
ldapadd -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x <<EOF
dn: uid=user4,cn=users,cn=accounts,${DS_SUFFIX_NAME}
uid: user4
givenName: User4
objectClass: inetorgperson
objectClass: inetuser
sn: User4
cn: User4
mail: user4@domain.local
userPassword: {CLEARTEXT}vaultwarden
nsAccountLock: TRUE
memberOf: cn=vaultwarden-users,cn=groups,cn=accounts,${DS_SUFFIX_NAME}
EOF
