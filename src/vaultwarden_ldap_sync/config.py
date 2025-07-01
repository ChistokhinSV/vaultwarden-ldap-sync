"""Central configuration dataclass loaded from environment variables.

Only parameters essential for the sync engine are included.  Anything used
*solely* during connectivity tests stays in :pyfile:`main.py` for now.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from .core.constants import (
    YES_VALUES,
    DEFAULT_LDAP_HOST,
    DEFAULT_VW_URL,
    DEFAULT_LDAP_GROUP_ATTR,
    DEFAULT_LDAP_MAIL_ATTR,
    DEFAULT_LDAP_DISABLED_ATTR,
    DEFAULT_LDAP_DISABLED_VALUES,
)


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val in YES_VALUES


def _env_list(name: str) -> List[str]:
    raw = os.getenv(name, "").strip()
    return [s for s in [p.strip() for p in raw.split(",")] if s]


@dataclass(slots=True)
class Config:
    """Runtime configuration derived from environment variables."""

    # LDAP --------------------------------------------------------------
    ldap_host: str = os.getenv('LDAP_HOST', DEFAULT_LDAP_HOST)
    ldap_bind_dn: str = os.getenv('LDAP_BIND_DN', '')
    ldap_bind_password: str = os.getenv('LDAP_BIND_PASSWORD', '')
    ldap_base_dn: str = os.getenv('LDAP_BASE_DN', '')

    ldap_object_type: str | None = os.getenv('LDAP_OBJECT_TYPE', None)
    ldap_user_groups: str | None = os.getenv('LDAP_USER_GROUPS', None)
    ldap_group_attr: str = os.getenv('LDAP_GROUP_ATTRIBUTE', DEFAULT_LDAP_GROUP_ATTR)
    ldap_filter: str | None = os.getenv('LDAP_FILTER', None)
    ldap_mail_attr: str = os.getenv('LDAP_MAIL_FIELD', DEFAULT_LDAP_MAIL_ATTR)
    ldap_disabled_attr: str | None = os.getenv('LDAP_DISABLED_ATTRIBUTE', DEFAULT_LDAP_DISABLED_ATTR)
    ldap_disabled_values: List[str] = field(default_factory=lambda: _env_list('LDAP_DISABLED_VALUES') or DEFAULT_LDAP_DISABLED_VALUES)
    ldap_missing_is_disabled: bool = _env_bool('LDAP_MISSING_IS_DISABLED', False)
    ldap_users_only: bool = _env_bool('LDAP_USERS_ONLY', False)

    ignore_ldaps_cert: bool = _env_bool('IGNORE_LDAPS_CERT', False)
    ldap_ca_file: str | None = os.getenv('LDAP_CA_FILE', None)

    # VaultWarden -------------------------------------------------------
    vw_url: str = os.getenv('VW_URL', DEFAULT_VW_URL)
    vw_client_id: str = os.getenv('VW_USER_CLIENT_ID', '')
    vw_client_secret: str = os.getenv('VW_USER_CLIENT_SECRET', '')
    vw_org_id: str = os.getenv('VW_ORG_ID', '')
    ignore_vw_cert: bool = _env_bool('IGNORE_VW_CERT', False)

    # Misc --------------------------------------------------------------
    prevent_self_lock: bool = _env_bool('PREVENT_SELF_LOCK', True)

    debug: str = os.getenv('DEBUG', '').upper()

    def __post_init__(self) -> None:
        # strip prefixes from org id if present
        if self.vw_org_id.startswith('organization.'):
            self.vw_org_id = self.vw_org_id.split('.')[1]

    @classmethod
    def parse_multi_org_config(cls):
        """Parse multi-organization configuration with inheritance from base config.
        
        Configuration inheritance model:
        1. Base config (no suffix) provides defaults for all settings
        2. Numbered configs (_1, _2, etc.) inherit base and override specifics
        3. Each complete config must have vw_org_id and ldap_user_groups to be valid
        4. Missing required fields = skip that configuration
        
        Environment variables:
        - Base: VW_ORG_ID, VW_USER_CLIENT_ID, VW_USER_CLIENT_SECRET, LDAP_USER_GROUPS
        - Derived: VW_ORG_ID_1, VW_USER_CLIENT_ID_2, LDAP_USER_GROUPS_3, etc.
        
        Returns:
            Dict[str, Dict[str, str]]: Config identifier -> complete config dict
            
        Examples:
            # Same client, different orgs and groups
            VW_ORG_ID=org1
            VW_USER_CLIENT_ID=client1
            VW_USER_CLIENT_SECRET=secret1
            LDAP_USER_GROUPS=cn=users1,dc=domain
            VW_ORG_ID_2=org2
            LDAP_USER_GROUPS_2=cn=users2,dc=domain
            
            Result: {
                'base': {'vw_org_id': 'org1', 'vw_client_id': 'client1', ...},
                '2': {'vw_org_id': 'org2', 'vw_client_id': 'client1', 'ldap_user_groups': 'cn=users2,dc=domain', ...}
            }
        """
        import os
        
        # Get base configuration (no suffix)
        base_config = {
            'vw_org_id': os.getenv('VW_ORG_ID', ''),
            'vw_client_id': os.getenv('VW_USER_CLIENT_ID', ''),
            'vw_client_secret': os.getenv('VW_USER_CLIENT_SECRET', ''),
            'ldap_user_groups': os.getenv('LDAP_USER_GROUPS', ''),
            'vw_url': os.getenv('VW_URL', cls().vw_url),  # Use default from Config class
            'ignore_vw_cert': os.getenv('IGNORE_VW_CERT', ''),
        }
        
        # Find all numbered suffixes in environment variables
        suffixes = set()
        for env_var in os.environ.keys():
            for prefix in ['VW_ORG_ID_', 'VW_USER_CLIENT_ID_', 'VW_USER_CLIENT_SECRET_', 'LDAP_USER_GROUPS_']:
                if env_var.startswith(prefix):
                    suffix = env_var[len(prefix):]
                    # Only accept numeric suffixes (1, 2, 3, etc.)
                    if suffix.isdigit():
                        suffixes.add(suffix)
        
        # Build complete configurations with inheritance
        complete_configs = {}
        
        # Add base config if it has required fields
        if base_config['vw_org_id'] and base_config['ldap_user_groups']:
            complete_configs['base'] = base_config.copy()
        
        # Process each numbered suffix
        for suffix in sorted(suffixes):
            # Start with base config and override with suffix-specific values
            derived_config = base_config.copy()
            
            # Override with suffix-specific values if they exist
            suffix_overrides = {
                'vw_org_id': os.getenv(f'VW_ORG_ID_{suffix}'),
                'vw_client_id': os.getenv(f'VW_USER_CLIENT_ID_{suffix}'),
                'vw_client_secret': os.getenv(f'VW_USER_CLIENT_SECRET_{suffix}'),
                'ldap_user_groups': os.getenv(f'LDAP_USER_GROUPS_{suffix}'),
                'vw_url': os.getenv(f'VW_URL_{suffix}'),
                'ignore_vw_cert': os.getenv(f'IGNORE_VW_CERT_{suffix}'),
            }
            
            # Apply non-empty overrides
            for key, value in suffix_overrides.items():
                if value:  # Only override if the value is not empty
                    derived_config[key] = value
            
            # Check if this configuration is complete and valid
            required_fields = ['vw_org_id', 'ldap_user_groups']
            if all(derived_config.get(field) for field in required_fields):
                # Also need at least client credentials for VaultWarden access
                if derived_config.get('vw_client_id') and derived_config.get('vw_client_secret'):
                    complete_configs[suffix] = derived_config
                else:
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning(f"Config block '{suffix}' missing VaultWarden credentials, skipping")
            else:
                import logging
                logger = logging.getLogger(__name__)
                logger.info(f"Config block '{suffix}' missing required fields {required_fields}, skipping")
        
        return complete_configs
