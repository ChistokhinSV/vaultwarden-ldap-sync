"""Shared constants across the application."""

# Truth value strings
YES_VALUES = ('1', 'TRUE', 'YES', 'ON', 'true', 'yes', 'on')

# Default configuration values
DEFAULT_SYNC_INTERVAL = 60
DEFAULT_MAX_FAILURES = 5
DEFAULT_LDAP_PORT = 389
DEFAULT_LDAP_GROUP_ATTR = 'memberOf'
DEFAULT_LDAP_MAIL_ATTR = 'mail'
DEFAULT_LDAP_DISABLED_ATTR = 'nsAccountLock'

# Default LDAP disabled values
DEFAULT_LDAP_DISABLED_VALUES = [
    'TRUE',
    'true', 
    '1',
    'yes',
    'YES',
]

# Default endpoints
DEFAULT_LDAP_HOST = 'ldap://localhost:389'
DEFAULT_VW_URL = 'http://localhost:8080'