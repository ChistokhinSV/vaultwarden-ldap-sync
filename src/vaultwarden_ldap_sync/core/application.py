"""Main application class for VaultWarden LDAP Sync.

This module provides the central Application class that orchestrates the sync process
with proper separation of concerns and dependency injection for testability.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional, Dict

from ..config import Config
from ..sync_engine import run_sync, assign_users_to_organizations, SyncActions
from ..ldap_client import fetch_users
from ..vw_client import VaultWardenClient

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    """Result of a synchronization operation."""
    success: bool
    actions_taken: SyncActions
    errors: list[str]
    duration: float
    timestamp: float
    config_id: Optional[str] = None  # For multi-org sync


@dataclass
class Application:
    """Main application class for VaultWarden LDAP synchronization.
    
    This class encapsulates the main sync logic with proper dependency injection
    for testing and maintains the sync state and configuration.
    
    Example:
        app = Application(config=Config())
        result = app.run_once()
        
        # Multi-org mode
        results = app.run_multi_org_sync()
    """
    config: Config
    
    def __post_init__(self):
        """Initialize application after dataclass creation."""
        self.logger = logging.getLogger(f"{__name__}.Application")
        self._sync_cycle_count = 0
        
    def run_once(self, 
                 ldap_client_override=None, 
                 vw_client_override=None) -> SyncResult:
        """Run a single synchronization cycle.
        
        Args:
            ldap_client_override: Optional LDAP client for testing
            vw_client_override: Optional VaultWarden client for testing
            
        Returns:
            SyncResult: Result of the sync operation
        """
        self._sync_cycle_count += 1
        cycle_id = f"sync-{self._sync_cycle_count}-{int(time.time())}"
        
        start_time = time.time()
        self.logger.info(f"Starting sync cycle {cycle_id}")
        
        try:
            # Check if auto-discovery mode should be used
            if not self.config.vw_org_id and self._should_use_auto_discovery():
                self.logger.info("No VW_ORG_ID specified but user filters found - using auto-discovery mode")
                return self._run_auto_discovery_sync(cycle_id, start_time, ldap_client_override, vw_client_override)
            
            # Standard single-org mode
            if not self.config.vw_org_id:
                raise ValueError("VW_ORG_ID is required for single-org mode. Either specify VW_ORG_ID or provide user filters for auto-discovery mode.")
            
            # Create or use provided clients
            if vw_client_override:
                vw_client = vw_client_override
            else:
                vw_client = VaultWardenClient(
                    url=self.config.vw_url,
                    client_id=self.config.vw_client_id,
                    client_secret=self.config.vw_client_secret,
                    org_id=self.config.vw_org_id,
                    ignore_cert=self.config.ignore_vw_cert
                )
            
            # Fetch LDAP users
            if ldap_client_override:
                ldap_users = ldap_client_override
            else:
                ldap_users = fetch_users(
                    host=self.config.ldap_host,
                    bind_dn=self.config.ldap_bind_dn,
                    bind_password=self.config.ldap_bind_password,
                    base_dn=self.config.ldap_base_dn,
                    groups=self.config.ldap_user_groups,
                    object_type=self.config.ldap_object_type,
                    group_attr=self.config.ldap_group_attr,
                    additional_filter=self.config.ldap_filter,
                    email_attr=self.config.ldap_mail_attr,
                    disabled_attr=self.config.ldap_disabled_attr,
                    disabled_values=self.config.ldap_disabled_values,
                    missing_is_disabled=self.config.ldap_missing_is_disabled,
                    ignore_cert=self.config.ignore_vw_cert,
                )
            
            # Run sync
            actions = run_sync(self.config)
            
            duration = time.time() - start_time
            self.logger.info(f"Sync cycle {cycle_id} completed successfully in {duration:.2f}s")
            
            return SyncResult(
                success=True,
                actions_taken=actions,
                errors=[],
                duration=duration,
                timestamp=start_time
            )
            
        except Exception as exc:
            duration = time.time() - start_time
            error_msg = f"Sync cycle {cycle_id} failed: {exc}"
            self.logger.error(error_msg)
            
            return SyncResult(
                success=False,
                actions_taken=SyncActions(invite=set(), revoke=set(), restore=set()),
                errors=[str(exc)],
                duration=duration,
                timestamp=start_time
            )
    
    def run_multi_org_sync(self) -> Dict[str, SyncResult]:
        """Run synchronization across multiple organizations.
        
        Uses the inheritance-based multi-org configuration to sync
        different LDAP groups to different VaultWarden organizations.
        
        Returns:
            Dict[str, SyncResult]: Config ID -> sync result
        """
        self._sync_cycle_count += 1
        cycle_id = f"multi-sync-{self._sync_cycle_count}-{int(time.time())}"
        
        self.logger.info(f"Starting multi-organization sync cycle {cycle_id}")
        
        # Get user assignments for each configuration
        config_assignments = assign_users_to_organizations(self.config)
        
        if not config_assignments:
            self.logger.warning(f"No multi-org configurations found in cycle {cycle_id}")
            return {}
        
        # Get multi-org configurations
        multi_configs = Config.parse_multi_org_config()
        results = {}
        
        for config_id, user_emails in config_assignments.items():
            org_config = multi_configs.get(config_id)
            if not org_config:
                self.logger.error(f"Config {config_id} not found in multi-org configs")
                continue
            
            self.logger.info(f"Syncing config '{config_id}' with {len(user_emails)} users to org {org_config.get('vw_org_id')}")
            
            start_time = time.time()
            
            try:
                # Create VaultWarden client for this organization
                vw_client = VaultWardenClient(
                    url=org_config.get('vw_url', self.config.vw_url),
                    client_id=org_config['vw_client_id'],
                    client_secret=org_config['vw_client_secret'],
                    org_id=org_config['vw_org_id'],
                    ignore_cert=org_config.get('ignore_vw_cert', self.config.ignore_vw_cert)
                )
                
                # Fetch LDAP users for this configuration
                ldap_users = fetch_users(
                    host=self.config.ldap_host,
                    bind_dn=self.config.ldap_bind_dn,
                    bind_password=self.config.ldap_bind_password,
                    base_dn=self.config.ldap_base_dn,
                    groups=org_config['ldap_user_groups'],
                    object_type=self.config.ldap_object_type,
                    group_attr=self.config.ldap_group_attr,
                    filter_override=self.config.ldap_filter,
                    mail_attr=self.config.ldap_mail_attr,
                    disabled_attr=self.config.ldap_disabled_attr,
                    disabled_values=self.config.ldap_disabled_values,
                    missing_is_disabled=self.config.ldap_missing_is_disabled,
                    users_only=self.config.ldap_users_only,
                )
                
                # Run sync for this configuration
                actions = run_sync(
                    config=self.config,
                    ldap_users=ldap_users,
                    vw_client=vw_client
                )
                
                duration = time.time() - start_time
                self.logger.info(f"Config '{config_id}' sync completed in {duration:.2f}s")
                
                results[config_id] = SyncResult(
                    success=True,
                    actions_taken=actions,
                    errors=[],
                    duration=duration,
                    timestamp=start_time,
                    config_id=config_id
                )
                
            except Exception as exc:
                duration = time.time() - start_time
                error_msg = f"Config '{config_id}' sync failed: {exc}"
                self.logger.error(error_msg)
                
                results[config_id] = SyncResult(
                    success=False,
                    actions_taken=SyncActions(invite=set(), revoke=set(), restore=set()),
                    errors=[str(exc)],
                    duration=duration,
                    timestamp=start_time,
                    config_id=config_id
                )
        
        total_successful = sum(1 for result in results.values() if result.success)
        total_configs = len(results)
        
        self.logger.info(f"Multi-org sync cycle {cycle_id} completed: {total_successful}/{total_configs} configs successful")
        
        return results
    
    def run_loop(self, sync_interval: Optional[int] = None, max_failures: Optional[int] = None) -> None:
        """Run continuous synchronization loop.
        
        Args:
            sync_interval: Seconds between sync cycles (default from config)
            max_failures: Max consecutive failures before exit (default from config)
        """
        from ..core.constants import DEFAULT_SYNC_INTERVAL, DEFAULT_MAX_FAILURES
        
        interval = sync_interval or int(os.getenv('SYNC_INTERVAL', DEFAULT_SYNC_INTERVAL))
        max_fails = max_failures or int(os.getenv('MAX_CONSECUTIVE_FAILURES', DEFAULT_MAX_FAILURES))
        
        self.logger.info(f"Starting sync loop: interval={interval}s, max_failures={max_fails}")
        
        consecutive_failures = 0
        
        while True:
            try:
                # Check if multi-org mode is enabled
                multi_org_enabled = os.getenv('MULTI_ORG_MODE', '').lower() in ('1', 'true', 'yes', 'on')
                
                if multi_org_enabled:
                    results = self.run_multi_org_sync()
                    # Consider multi-org cycle successful if any config succeeded
                    success = any(result.success for result in results.values())
                else:
                    result = self.run_once()
                    success = result.success
                
                if success:
                    consecutive_failures = 0
                else:
                    consecutive_failures += 1
                    self.logger.warning(f"Consecutive failures: {consecutive_failures}/{max_fails}")
                    
                    if consecutive_failures >= max_fails:
                        self.logger.error(f"Max consecutive failures ({max_fails}) reached, exiting")
                        break
                
                # Check for run-once mode
                if os.getenv('RUN_ONCE', '').lower() in ('1', 'true', 'yes', 'on'):
                    self.logger.info("RUN_ONCE mode enabled, exiting after single cycle")
                    break
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal, shutting down gracefully")
                break
            except Exception as exc:
                consecutive_failures += 1
                self.logger.error(f"Unexpected error in sync loop: {exc}")
                
                if consecutive_failures >= max_fails:
                    self.logger.error(f"Max consecutive failures ({max_fails}) reached, exiting")
                    break
                    
                time.sleep(interval)
    
    def shutdown(self) -> None:
        """Gracefully shutdown the application."""
        self.logger.info("Application shutdown requested")
        # In the future, this could clean up resources, connections, etc.
    
    def _should_use_auto_discovery(self) -> bool:
        """Check if auto-discovery mode should be used.
        
        Auto-discovery is used when:
        1. VW_ORG_ID is not specified (empty)
        2. AND user filters are specified (LDAP_USER_GROUPS or LDAP_FILTER)
        
        Returns:
            bool: True if auto-discovery should be used
        """
        has_user_filters = bool(self.config.ldap_user_groups or self.config.ldap_filter)
        return has_user_filters
    
    def _run_auto_discovery_sync(self, cycle_id: str, start_time: float, 
                                ldap_client_override=None, vw_client_override=None) -> SyncResult:
        """Run sync in auto-discovery mode - sync to all manageable organizations.
        
        Args:
            cycle_id: Unique identifier for this sync cycle
            start_time: Start time of the sync cycle
            ldap_client_override: Optional LDAP client for testing
            vw_client_override: Optional VaultWarden client for testing
            
        Returns:
            SyncResult: Aggregated result of syncing to all organizations
        """
        # First, create a temporary VaultWarden client to discover organizations
        # We'll use the first available org temporarily to get the client working
        temp_client = None
        
        try:
            # Create a VaultWarden client without specifying org_id to discover orgs
            temp_client = VaultWardenClient(
                url=self.config.vw_url,
                client_id=self.config.vw_client_id,
                client_secret=self.config.vw_client_secret,
                org_id="00000000-0000-0000-0000-000000000000",  # Dummy org ID for discovery
                ignore_cert=self.config.ignore_vw_cert
            )
        except Exception:
            # If that fails, we need to try a different approach
            pass
        
        # Discover manageable organizations
        if vw_client_override:
            manageable_orgs = vw_client_override.list_manageable_organizations()
        else:
            # For auto-discovery, we first need to get any valid org ID from the profile
            # Then we can create a proper client to list all manageable orgs
            from ..vw_client import VaultWardenClient
            
            # Create a client using the BitwardenAPIClient directly for profile access
            from vaultwarden.clients.bitwarden import BitwardenAPIClient as _BWClient
            
            # Create the underlying Bitwarden client
            bw_client = _BWClient(
                url=self.config.vw_url,
                email="dummy@example.invalid",
                password="unused",  
                client_id=self.config.vw_client_id,
                client_secret=self.config.vw_client_secret,
                device_id="vaultwarden-ldap-sync",
                timeout=30
            )
            
            # Get profile to find organizations
            response = bw_client.api_request(method="GET", path="/api/accounts/profile")
            if hasattr(response, 'json'):
                profile_data = response.json()
            else:
                profile_data = response
                
            organizations = profile_data.get('organizations', [])
            manageable_orgs = []
            
            for org in organizations:
                if org.get('status', 0) >= 2:  # Owner/admin level
                    manageable_orgs.append({
                        'id': org.get('id'),
                        'name': org.get('name'),
                        'status': org.get('status'),
                        'type': org.get('type', 0),
                        'enabled': org.get('enabled', True)
                    })
        
        if not manageable_orgs:
            raise ValueError("Auto-discovery mode: No manageable organizations found for the specified credentials")
        
        self.logger.info(f"Auto-discovery found {len(manageable_orgs)} manageable organizations")
        
        # Fetch LDAP users once
        if ldap_client_override:
            ldap_users = ldap_client_override
        else:
            ldap_users = fetch_users(
                host=self.config.ldap_host,
                bind_dn=self.config.ldap_bind_dn,
                bind_password=self.config.ldap_bind_password,
                base_dn=self.config.ldap_base_dn,
                groups=self.config.ldap_user_groups,
                object_type=self.config.ldap_object_type,
                group_attr=self.config.ldap_group_attr,
                additional_filter=self.config.ldap_filter,
                email_attr=self.config.ldap_mail_attr,
                disabled_attr=self.config.ldap_disabled_attr,
                disabled_values=self.config.ldap_disabled_values,
                missing_is_disabled=self.config.ldap_missing_is_disabled,
                ignore_cert=self.config.ignore_vw_cert,
            )
        
        # Sync to each manageable organization
        total_actions = SyncActions(invite=set(), revoke=set(), restore=set())
        errors = []
        successful_orgs = 0
        
        for org in manageable_orgs:
            org_id = org['id']
            org_name = org['name']
            
            try:
                self.logger.info(f"Auto-discovery: Syncing to organization '{org_name}' ({org_id})")
                
                # Create VaultWarden client for this specific organization
                org_client = VaultWardenClient(
                    url=self.config.vw_url,
                    client_id=self.config.vw_client_id,
                    client_secret=self.config.vw_client_secret,
                    org_id=org_id,
                    ignore_cert=self.config.ignore_vw_cert
                )
                
                # Create a temporary config for this specific organization
                from dataclasses import replace
                org_config = replace(self.config, vw_org_id=org_id)
                
                # Run sync for this organization
                org_actions = run_sync(org_config)
                
                # Aggregate actions
                total_actions.invite.update(org_actions.invite)
                total_actions.revoke.update(org_actions.revoke)  
                total_actions.restore.update(org_actions.restore)
                
                successful_orgs += 1
                self.logger.info(f"Auto-discovery: Successfully synced to '{org_name}' - "
                               f"invited: {len(org_actions.invite)}, "
                               f"revoked: {len(org_actions.revoke)}, "
                               f"restored: {len(org_actions.restore)}")
                
            except Exception as exc:
                error_msg = f"Auto-discovery: Failed to sync to organization '{org_name}' ({org_id}): {exc}"
                self.logger.error(error_msg)
                errors.append(error_msg)
        
        # Calculate final result
        duration = time.time() - start_time
        success = successful_orgs > 0  # Success if at least one org was synced
        
        if success:
            self.logger.info(f"Auto-discovery sync cycle {cycle_id} completed: "
                           f"{successful_orgs}/{len(manageable_orgs)} organizations synced successfully in {duration:.2f}s")
        else:
            self.logger.error(f"Auto-discovery sync cycle {cycle_id} failed: "
                            f"No organizations synced successfully out of {len(manageable_orgs)} in {duration:.2f}s")
        
        return SyncResult(
            success=success,
            actions_taken=total_actions,
            errors=errors,
            duration=duration,
            timestamp=start_time
        )