# VaultWarden-LDAP-Sync Testing Infrastructure

This guide describes the comprehensive testing infrastructure for VaultWarden-LDAP-Sync, including development containers, integration tests, and CI/CD pipelines.

---

## Testing Overview

The testing infrastructure provides:
- **Comprehensive Integration Tests** covering all sync scenarios
- **Containerized Test Environment** with LDAP and VaultWarden services
- **GitHub Actions CI/CD** with automated testing across Python versions
- **Local Development Testing** with Docker Compose
- **Test Data Management** with pre-populated test instances

---

## Test Architecture

### Test Categories

1. **Privilege Testing** - Sync user permissions and access control
2. **Multi-Organization** - Organization discovery and multi-org sync
3. **Error Handling** - SMTP failures, permission errors, service unavailability
4. **LDAP Scenarios** - User status, group membership, attribute handling
5. **Full Sync Cycles** - Complete invite/revoke/restore workflows

### Test Services

- **389ds LDAP Server** - Pre-populated with test users and groups
- **VaultWarden Instance** - Pre-configured with test organization
- **MailHog SMTP Server** - Email testing and verification
- **Test Runner** - Containerized pytest execution environment

---

## Quick Start - Integration Testing

### 1. Run Full Integration Test Suite

```sh
cd docker
# Start the complete test environment
docker compose -f docker-compose.test-full.yml up --build
```

This will:
- Start 389ds LDAP server with test data
- Start VaultWarden with pre-configured organization
- Start MailHog for email testing
- Run the complete integration test suite

### 2. Run Specific Test Categories

```sh
# Run privilege tests only
python -m pytest tests/integration/ -m "privileges" -v

# Run LDAP-specific tests
python -m pytest tests/integration/ -m "ldap" -v

# Run error handling tests
python -m pytest tests/integration/ -m "error_handling" -v

# Run multi-org tests (may skip if not implemented)
python -m pytest tests/integration/ -m "multi_org" -v
```

### 3. Individual Service Testing

**LDAP Server Only:**
```sh
docker compose -f docker-compose.389ds.yml up -d
python -m pytest tests/integration/test_ldap_client_fetch.py -v
```

**VaultWarden Only:**
```sh
docker compose -f docker-compose.vaultwarden.yml up -d
# Manual VW testing via web UI at http://localhost:8080
```

---

## Test Data Structure

### LDAP Test Users

| User | Email | Status | Groups | Purpose |
|------|-------|--------|---------|---------|
| `user` | user@domain.local | Active | vaultwarden-users, vaultwarden-org1 | Basic sync testing |
| `user2` | user2@domain.local | Active | vaultwarden-users, vaultwarden-org1 | Multi-user scenarios |
| `user3` | user3@domain.local | Active | vaultwarden-org2 | Not in main sync group |
| `user4` | user4@domain.local | Disabled | vaultwarden-users, vaultwarden-org2 | Disabled user testing |
| `admin_user` | admin@domain.local | Active | vaultwarden-admins | Privilege testing |
| `limited_user` | limited@domain.local | Disabled | vaultwarden-mixed | Limited access testing |

### LDAP Test Groups

| Group | Members | Purpose |
|-------|---------|---------|
| `vaultwarden-users` | user, user2, user4 | Main sync group |
| `vaultwarden-org1` | user, user2 | Multi-org testing |
| `vaultwarden-org2` | user3, user4 | Multi-org testing |
| `vaultwarden-admins` | admin_user | Admin privilege testing |
| `vaultwarden-mixed` | user, limited_user, user4 | Mixed status testing |

### VaultWarden Test Configuration

- **Admin Token**: `$argon2id$v=19$m=65540,t=3,p=4$feGEx6pnYAk48r0C9gAhcRLEksQxZ09dZxlxpKz735I$9O66H64jds3g2fRxJTmazL7Kj0BPvaQ+0UVHsChJqJI`
- **Admin Password**: `vaultwarden`
- **Test Organization**: Pre-configured with test users
- **API Access**: Client ID/Secret for sync operations

---

## Development Testing

### Manual VaultWarden Setup (if needed)

1. **Start VaultWarden**
```sh
docker compose -f docker-compose.vaultwarden.yml up -d
```

2. **Access Web UI**
- Web UI: [http://localhost:8080](http://localhost:8080)
- Admin Panel: [http://localhost:8080/admin](http://localhost:8080/admin)

3. **Create Test Organization**
- Register user: `user@domain.local` / `vaultwarden1234`
- Create organization named `vaultwarden`
- Generate API credentials

4. **Backup Database**
```sh
docker exec -it ldap_sync_vaultwarden /vaultwarden backup
# Or manual backup:
cd /var/lib/docker/volumes/ldap_sync_vaultwarden_data/_data
sqlite3 db.sqlite3 ".backup './db-backup.sqlite3'"
```

## CI/CD Integration

### GitHub Actions Workflow

The repository includes a comprehensive CI/CD pipeline that:

1. **Matrix Testing** - Tests across Python 3.10, 3.11, 3.12
2. **Parallel Execution** - Runs different test categories in parallel
3. **Service Health Checks** - Ensures LDAP and VaultWarden are ready
4. **Coverage Reporting** - Generates coverage reports and uploads to Codecov
5. **Artifact Collection** - Collects logs and test results on failure

### Test Categories in CI

- **Unit Tests** - Fast tests without external dependencies
- **Integration Tests** - Full sync scenarios with real services
- **Privilege Tests** - User permission and access control validation
- **Multi-Org Tests** - Organization discovery and multi-org sync (when implemented)
- **Error Handling Tests** - Failure scenario validation

### Environment Variables for CI

```yaml
# LDAP Configuration
LDAP_HOST: ldap://ldap_sync_389ds:3389
LDAP_BIND_DN: cn=Directory Manager
LDAP_BIND_PASSWORD: adminpassword
LDAP_BASE_DN: dc=domain,dc=local

# VaultWarden Configuration  
VW_URL: http://ldap_sync_vaultwarden
VW_USER_CLIENT_ID: user_test_client_id
VW_USER_CLIENT_SECRET: user_test_client_secret
VW_ORG_ID: test_org_id
```

---

## Advanced Testing Scenarios

### Enhanced LDAP Test Data

The `test-data-setup.sh` script creates additional test scenarios:

- **Multi-Organization Groups** - Separate groups for different orgs
- **Admin Users** - Users with elevated privileges  
- **Mixed Status Groups** - Groups with active and disabled users
- **Privilege Testing Users** - Users for permission validation

### Custom Test Execution

```sh
# Run tests with specific environment
export LDAP_HOST=ldap://your-ldap-server:389
export VW_URL=http://your-vw-instance
python -m pytest tests/integration/ -v

# Run only privilege tests
python -m pytest tests/integration/test_scenarios.py::TestPrivilegeScenarios -v

# Run with coverage
python -m pytest tests/ --cov=src/vaultwarden_ldap_sync --cov-report=html
```

### Test Markers

Use pytest markers for selective testing:

```sh
# Integration tests only
python -m pytest -m integration

# Fast unit tests only  
python -m pytest -m "unit and not slow"

# LDAP connectivity tests
python -m pytest -m ldap

# Error handling scenarios
python -m pytest -m error_handling
```

---

## Building Enhanced Test Images

### Enhanced 389ds Image

```sh
# Build enhanced LDAP test image
docker build -t your-registry/389ds-test-enhanced:latest -f Dockerfile.test-enhanced .

# Push to registry
docker push your-registry/389ds-test-enhanced:latest
```

### Pre-Populated VaultWarden Image

```sh
# Build VaultWarden with test data
docker build -t your-registry/vaultwarden-test-populated:latest -f Dockerfile.vw-populated .

# Push to registry  
docker push your-registry/vaultwarden-test-populated:latest
```

---

## Troubleshooting

### Common Issues

1. **Services Not Ready**
   - Check health checks are passing
   - Increase timeout values if needed
   - Verify port availability

2. **LDAP Connection Failures**
   - Ensure 389ds container is fully started
   - Check LDAP credentials and base DN
   - Verify test data was loaded correctly

3. **VaultWarden API Errors**
   - Confirm admin token is correct
   - Check organization and user setup
   - Verify API client credentials

### Debug Commands

```sh
# Check LDAP data
ldapsearch -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w adminpassword -b "dc=domain,dc=local" "(objectClass=*)"

# Check VaultWarden health
curl -f http://localhost:8080/alive

# View container logs
docker compose -f docker-compose.test-full.yml logs ldap_sync_389ds
docker compose -f docker-compose.test-full.yml logs ldap_sync_vaultwarden
```

---

## Notes

- All test containers use the `ldap_sync_` prefix for consistency
- Test data is automatically created by the enhanced setup scripts
- CI/CD pipeline handles service orchestration and cleanup
- Local testing mirrors the CI/CD environment for consistency
