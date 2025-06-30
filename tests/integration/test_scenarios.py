"""
Comprehensive integration test scenarios covering all todo cases.
Tests run against containerized LDAP and VaultWarden instances.
"""
import os
import time
from pathlib import Path
from typing import Dict, List, Set
import pytest
from dataclasses import dataclass

from vaultwarden_ldap_sync.config import Config
from vaultwarden_ldap_sync.ldap_client import fetch_users
from vaultwarden_ldap_sync.vw_client import VaultWardenClient
from vaultwarden_ldap_sync.sync_engine import run_sync


@dataclass
class TestScenario:
    """Represents a test scenario with expected outcomes."""
    name: str
    description: str
    ldap_users: Set[str]  # Expected LDAP users
    vw_users: Set[str]    # Expected VW users before sync
    expected_invites: Set[str]  # Expected invites after sync
    expected_revokes: Set[str]  # Expected revokes after sync
    expected_restores: Set[str] # Expected restores after sync


class IntegrationTestBase:
    """Base class for integration tests with common setup."""
    
    @classmethod
    def setup_class(cls):
        """Set up test environment variables."""
        cls._setup_ldap_env()
        cls._setup_vw_env()
        cls.config = Config()
        cls.vw_client = VaultWardenClient(
            url=cls.config.vw_url,
            client_id=cls.config.vw_user_client_id,
            client_secret=cls.config.vw_user_client_secret,
            org_id=cls.config.vw_org_id,
        )
    
    @staticmethod
    def _setup_ldap_env():
        """Configure LDAP environment variables."""
        defaults = {
            'LDAP_HOST': 'ldap://localhost:3389',
            'LDAP_BIND_DN': 'cn=Directory Manager',
            'LDAP_BIND_PASSWORD': 'adminpassword',
            'LDAP_BASE_DN': 'dc=domain,dc=local',
            'LDAP_GROUPS': 'cn=vaultwarden-users,cn=groups,cn=accounts,dc=domain,dc=local',
        }
        for key, value in defaults.items():
            os.environ.setdefault(key, value)
    
    @staticmethod
    def _setup_vw_env():
        """Configure VaultWarden environment variables."""
        defaults = {
            'VW_URL': 'http://localhost:8080',
            'VW_USER_CLIENT_ID': 'user_test_client_id',
            'VW_USER_CLIENT_SECRET': 'user_test_client_secret',
            'VW_ORG_ID': 'test_org_id',
            'PREVENT_SELF_LOCK': '1',
            'RUN_ONCE': '1',
        }
        for key, value in defaults.items():
            os.environ.setdefault(key, value)
    
    def wait_for_services(self, timeout: int = 30):
        """Wait for LDAP and VaultWarden services to be ready."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Test LDAP connectivity
                fetch_users(
                    host=self.config.ldap_host,
                    bind_dn=self.config.ldap_bind_dn,
                    bind_password=self.config.ldap_bind_password,
                    base_dn=self.config.ldap_base_dn,
                )
                # Test VW connectivity
                self.vw_client.list_users()
                return True
            except Exception:
                time.sleep(1)
        return False
    
    def reset_vw_org_users(self):
        """Reset VaultWarden org to clean state."""
        # Remove all users except the sync user
        users = self.vw_client.list_users()
        sync_user_email = os.getenv('VW_SYNC_USER_EMAIL', 'sync@domain.local')
        
        for user_id, user in users.items():
            if user.email != sync_user_email:
                try:
                    self.vw_client.revoke(user_id)
                except Exception:
                    pass


class TestPrivilegeScenarios(IntegrationTestBase):
    """Test sync user privilege scenarios."""
    
    def test_sync_user_invite_privileges(self):
        """Test what privileges the sync user needs for inviting users."""
        self.reset_vw_org_users()
        
        # Try to invite a new user
        test_email = 'privilege_test@domain.local'
        
        try:
            self.vw_client.invite(test_email)
            # If successful, sync user has invite privileges
            assert True, 'Sync user has invite privileges'
        except Exception as e:
            pytest.fail(f'Sync user lacks invite privileges: {e}')
    
    def test_sync_user_revoke_privileges(self):
        """Test sync user revoke privileges."""
        # First invite a user, then try to revoke
        test_email = 'revoke_test@domain.local'
        
        try:
            self.vw_client.invite(test_email)
            users = self.vw_client.list_users()
            
            # Find the test user
            test_user_id = None
            for user_id, user in users.items():
                if user.email == test_email:
                    test_user_id = user_id
                    break
            
            if test_user_id:
                self.vw_client.revoke(test_user_id)
                assert True, 'Sync user has revoke privileges'
            else:
                pytest.fail('Could not find test user to revoke')
                
        except Exception as e:
            pytest.fail(f'Sync user lacks revoke privileges: {e}')


class TestOrganizationDiscovery(IntegrationTestBase):
    """Test organization discovery and multi-org scenarios."""
    
    def test_auto_discovery_organizations(self):
        """Test auto-discovery of organizations user can manage."""
        # This test requires VW API to list orgs the user can manage
        try:
            orgs = self.vw_client.list_manageable_organizations()
            assert isinstance(orgs, list), 'Should return list of organizations'
            assert len(orgs) > 0, 'Should find at least one manageable organization'
        except NotImplementedError:
            pytest.skip('Organization discovery not yet implemented')
    
    def test_remove_fixed_org_id_config(self):
        """Test function to remove fixed organization ID from config."""
        # Test with fixed org ID
        config_with_fixed = Config()
        assert config_with_fixed.vw_org_id is not None
        
        # Test without fixed org ID (should use auto-discovery)
        os.environ.pop('VW_ORG_ID', None)
        config_auto = Config()
        # Should either be None or auto-discovered
        assert config_auto.vw_org_id is None or isinstance(config_auto.vw_org_id, str)


class TestMultiOrgScenarios(IntegrationTestBase):
    """Test multi-organization scenarios."""
    
    def test_multi_org_config_parsing(self):
        """Test config parser for VW_USER_CLIENT_ID_* and VW_ORG_ID_* sections."""
        # Set up multi-org environment variables
        os.environ.update({
            'VW_USER_CLIENT_ID_ORG1': 'client_id_org1',
            'VW_USER_CLIENT_SECRET_ORG1': 'client_secret_org1',
            'VW_ORG_ID_ORG1': 'org_id_1',
            'VW_USER_CLIENT_ID_ORG2': 'client_id_org2',
            'VW_USER_CLIENT_SECRET_ORG2': 'client_secret_org2',
            'VW_ORG_ID_ORG2': 'org_id_2',
        })
        
        # Test multi-org config parsing
        try:
            multi_configs = Config.parse_multi_org_config()
            assert len(multi_configs) == 2
            assert 'ORG1' in multi_configs
            assert 'ORG2' in multi_configs
        except NotImplementedError:
            pytest.skip('Multi-org config parsing not yet implemented')
    
    def test_ldap_group_org_assignment(self):
        """Test LDAP group-based organization assignment logic."""
        # Set up group-based org assignment
        os.environ.update({
            'LDAP_GROUPS_ORG1': 'cn=vw-org1,cn=groups,cn=accounts,dc=domain,dc=local',
            'LDAP_GROUPS_ORG2': 'cn=vw-org2,cn=groups,cn=accounts,dc=domain,dc=local',
        })
        
        try:
            # Test group-based assignment logic - this function doesn't exist yet
            pytest.skip('LDAP group-based org assignment not yet implemented')
        except NotImplementedError:
            pytest.skip('LDAP group-based org assignment not yet implemented')


class TestErrorHandlingScenarios(IntegrationTestBase):
    """Test error handling scenarios."""
    
    def test_insufficient_privileges_error_handling(self):
        """Test error handling when invite operations fail due to permissions."""
        # Mock insufficient privileges by using invalid credentials
        original_secret = os.environ.get('VW_USER_CLIENT_SECRET')
        os.environ['VW_USER_CLIENT_SECRET'] = 'invalid_secret'
        
        try:
            invalid_client = VaultWardenClient()
            with pytest.raises(Exception) as exc_info:
                invalid_client.invite('test@domain.local')
            
            # Should get meaningful error message
            assert 'permission' in str(exc_info.value).lower() or 'unauthorized' in str(exc_info.value).lower()
            
        finally:
            # Restore original secret
            if original_secret:
                os.environ['VW_USER_CLIENT_SECRET'] = original_secret
    
    def test_smtp_server_unavailable_handling(self):
        """Test invite behavior when VaultWarden SMTP is configured but fails."""
        # This test requires VW to be configured with unreachable SMTP server
        pytest.skip('Requires VW configured with unreachable SMTP server')
    
    def test_smtp_misconfigured_handling(self):
        """Test invite behavior when VaultWarden SMTP is misconfigured."""
        # This test requires VW to be configured with invalid SMTP settings
        pytest.skip('Requires VW configured with invalid SMTP settings')


class TestLdapUserStatusScenarios(IntegrationTestBase):
    """Test LDAP user status and filtering scenarios."""
    
    def test_disabled_user_filtering(self):
        """Test that disabled LDAP users are properly filtered."""
        users = fetch_users(
            host=self.config.ldap_host,
            bind_dn=self.config.ldap_bind_dn,
            bind_password=self.config.ldap_bind_password,
            base_dn=self.config.ldap_base_dn,
            groups=getattr(self.config, 'ldap_groups', None),
        )
        
        # user4 should be disabled
        user4 = next((u for u in users if 'user4' in u.dn), None)
        assert user4 is not None, 'user4 should exist in LDAP'
        assert user4.disabled is True, 'user4 should be disabled'
        
        # Other users should be enabled
        active_users = [u for u in users if not u.disabled]
        assert len(active_users) >= 3, 'Should have at least 3 active users'
    
    def test_missing_disabled_attribute_behavior(self):
        """Test behavior when LDAP users lack disabled attribute."""
        users = fetch_users(
            host=self.config.ldap_host,
            bind_dn=self.config.ldap_bind_dn,
            bind_password=self.config.ldap_bind_password,
            base_dn=self.config.ldap_base_dn,
            groups=getattr(self.config, 'ldap_groups', None),
        )
        
        # Users without disabled attribute should default to enabled
        users_without_attr = [u for u in users if 'user1' in u.dn or 'user2' in u.dn]
        for user in users_without_attr:
            assert user.disabled is False, f'{user.dn} should default to enabled'
    
    def test_missing_is_disabled_flag(self):
        """Test missing_is_disabled flag behavior."""
        # Test with missing_is_disabled=True
        os.environ['LDAP_MISSING_IS_DISABLED'] = '1'
        config = Config()
        
        users = fetch_users(
            host=config.ldap_host,
            bind_dn=config.ldap_bind_dn,
            bind_password=config.ldap_bind_password,
            base_dn=config.ldap_base_dn,
            groups=getattr(config, 'ldap_groups', None),
            missing_is_disabled=True,
        )
        
        # Users without disabled attribute should now be considered disabled
        for user in users:
            if 'user4' not in user.dn:  # user4 is explicitly disabled
                # Other users should be considered disabled due to missing attribute
                assert user.disabled is True, f'{user.dn} should be disabled when missing_is_disabled=True'


class TestFullSyncScenarios(IntegrationTestBase):
    """Test complete sync scenarios."""
    
    def test_full_sync_invite_revoke_restore(self):
        """Test complete sync cycle with invite, revoke, and restore operations."""
        self.reset_vw_org_users()
        
        # Run initial sync
        result = run_sync(self.config)
        
        # Verify sync completed successfully
        assert result is not None, 'Sync should complete successfully'
        
        # Verify expected users were invited
        vw_users = self.vw_client.list_users()
        expected_emails = {'user@domain.local', 'user2@domain.local'}  # user4 disabled, user3 not in group
        
        invited_emails = {user.email for user in vw_users.values() if user.email in expected_emails}
        assert expected_emails.issubset(invited_emails), f'Expected users should be invited: {expected_emails - invited_emails}'
    
    def test_sync_with_different_ldap_groups(self):
        """Test multi-org feature with different LDAP group filters per organization."""
        # Set up different groups for different orgs
        os.environ.update({
            'LDAP_GROUPS_ORG1': 'cn=vw-org1,cn=groups,cn=accounts,dc=domain,dc=local',
            'LDAP_GROUPS_ORG2': 'cn=vw-org2,cn=groups,cn=accounts,dc=domain,dc=local',
        })
        
        pytest.skip('Requires multi-org implementation and test group setup')


@pytest.fixture(scope='session')
def integration_test_env():
    """Set up integration test environment."""
    test_base = IntegrationTestBase()
    test_base.setup_class()
    
    # Wait for services to be ready
    if not test_base.wait_for_services():
        pytest.skip('Test services not available')
    
    return test_base


# Test execution markers
pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
]