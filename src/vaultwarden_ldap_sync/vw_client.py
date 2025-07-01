"""Thin wrapper around *python-vaultwarden* to hide raw REST paths.

Only the subset of the Bitwarden / VaultWarden API that the sync engine
requires is implemented:

* list users in an organisation (and their status)
* invite user to organisation
* revoke user access
* restore user (undo revoke)

The wrapper also exposes a helper to discover *our* e-mail address based on the
user‐client UUID so the PREVENT_SELF_LOCK logic can mark it safe.
"""
from __future__ import annotations

from dataclasses import dataclass
import httpx
from typing import Dict, List
from uuid import UUID

from vaultwarden.clients.bitwarden import BitwardenAPIClient as _BWClient
from vaultwarden.models.bitwarden import Organization, get_organization


@dataclass(slots=True)
class OrgUser:
    """Simplified representation of an organisation user."""

    id: UUID  # organisation *user* id (not account id)
    email: str
    status: int  # 0 = active, -1 = revoked, 2 = owner, etc.

    @property
    def revoked(self) -> bool:
        return self.status == -1

    @property
    def active(self) -> bool:
        return self.status == 0 or self.status == 2  # treat owner as active


class VaultWardenClient:
    """Facade around *python-vaultwarden* for the sync engine."""

    def __init__(
        self,
        *,
        url: str,
        client_id: str,
        client_secret: str,
        org_id: str,
        ignore_cert: bool = False,
    ) -> None:
        # BitwardenAPIClient still demands email / password – provide dummies
        # When TLS verification is disabled we monkey-patch httpx so every request
        # defaults to verify=False.  This works regardless of *python-vaultwarden*
        # internals and avoids passing unsupported kwargs.
        if ignore_cert:
            _patch_httpx_no_verify()

        bw_kwargs = dict(
            url=url,
            email="dummy@example.invalid",
            password="unused",
            client_id=client_id,
            client_secret=client_secret,
            device_id="vaultwarden-ldap-sync",
        )
        self._bw = _BWClient(**bw_kwargs)

        self._org: Organization = get_organization(self._bw, org_id)

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------
    def list_users(self, force: bool = False) -> List[OrgUser]:
        """Return *all* users in the organisation as :class:`OrgUser`."""
        users = self._org.users(force_refresh=force)
        return [OrgUser(id=u.Id, email=u.Email, status=u.Status) for u in users]

    def user_map(self, force: bool = False) -> Dict[str, OrgUser]:
        """Mapping *email → OrgUser* for quick lookups."""
        return {u.email.lower(): u for u in self.list_users(force)}

    def our_email(self, user_uuid: str | None = None) -> str | None:
        """Best-effort detection of the service-account e-mail.

        We inspect organisation users and compare their ``UserId`` with the
        UUID portion of the *user.* client id.  Returns the e-mail address or
        ``None`` if not found.
        """
        if not user_uuid:
            return None
        try:
            uuid_obj = UUID(user_uuid)
        except ValueError:
            return None
        for user in self._org.users():  # list_users gives org-user not account
            if getattr(user, "UserId", None) == uuid_obj:
                return user.Email
        return None

    # ------------------------------------------------------------------
    # Mutating operations – info logging should be done by caller
    # ------------------------------------------------------------------
    def invite(self, email: str) -> None:
        try:
            self._org.invite(
                email=email,
                collections=[],
                default_readonly=True,
                default_hide_passwords=True,
            )
        except Exception as exc:
            # Try to extract HTTP response details if available
            response_details = self._extract_http_error(exc)
            raise Exception(f'Failed to invite {email}: {exc}{response_details}') from exc

    def revoke(self, org_user_id: UUID) -> None:
        try:
            self._bw.api_request(
                method="PUT",
                path=f"/api/organizations/{self._org.Id}/users/{org_user_id}/revoke",
            )
        except Exception as exc:
            # Try to extract HTTP response details if available
            response_details = self._extract_http_error(exc)
            raise Exception(f'Failed to revoke user {org_user_id}: {exc}{response_details}') from exc

    def restore(self, org_user_id: UUID) -> None:
        try:
            self._bw.api_request(
                method="PUT",
                path=f"/api/organizations/{self._org.Id}/users/{org_user_id}/restore",
            )
        except Exception as exc:
            # Try to extract HTTP response details if available
            response_details = self._extract_http_error(exc)
            raise Exception(f'Failed to restore user {org_user_id}: {exc}{response_details}') from exc

    def _extract_http_error(self, exc: Exception) -> str:
        """Extract HTTP response details from various exception types."""
        details = []
        
        # Check for httpx.HTTPStatusError (most common)
        if hasattr(exc, 'response'):
            response = exc.response
            try:
                details.append(f' [HTTP {response.status_code}]')
                if hasattr(response, 'text'):
                    response_text = response.text.strip()
                    if response_text:
                        details.append(f' Response: {response_text}')
                elif hasattr(response, 'content'):
                    response_content = response.content.decode('utf-8', errors='ignore').strip()
                    if response_content:
                        details.append(f' Response: {response_content}')
            except Exception:
                details.append(' [Could not decode response]')
        
        # Check for requests-style exceptions
        elif hasattr(exc, 'response') and exc.response is not None:
            try:
                response = exc.response
                details.append(f' [HTTP {response.status_code}]')
                if hasattr(response, 'text'):
                    details.append(f' Response: {response.text}')
            except Exception:
                details.append(' [Could not decode response]')
        
        # Check if it's already a detailed error message
        elif 'HTTP' in str(exc) and ('400' in str(exc) or '401' in str(exc) or '403' in str(exc) or '500' in str(exc)):
            # Already has HTTP details, don't duplicate
            pass
        
        return ''.join(details)


# ---------------------------------------------------------------------------
# Helpers – TLS verification patch
# ---------------------------------------------------------------------------

def _patch_httpx_no_verify() -> None:  # noqa: D401 – helper
    """Monkey-patch **httpx** so all outgoing requests skip TLS verification.

    The patch is applied only once per interpreter. It forces default
    keyword ``verify=False`` on high-level convenience functions and on both
    ``httpx.Client`` and ``httpx.AsyncClient`` constructors. This is enough
    to cover all calls made by *python-vaultwarden*.
    """
    if getattr(httpx, "_vw_no_verify_patch", False):
        return

    orig_request = httpx.request

    def _request(method, url, *args, **kwargs):  # type: ignore[override]
        kwargs.setdefault("verify", False)
        return orig_request(method, url, *args, **kwargs)

    httpx.request = _request  # type: ignore[assignment]

    orig_client_init = httpx.Client.__init__

    def _client_init(self, *a, **k):  # type: ignore[no-self-use]
        k.setdefault("verify", False)
        orig_client_init(self, *a, **k)  # type: ignore[misc]

    httpx.Client.__init__ = _client_init  # type: ignore[assignment]

    orig_async_init = httpx.AsyncClient.__init__

    def _async_init(self, *a, **k):  # type: ignore[no-self-use]
        k.setdefault("verify", False)
        orig_async_init(self, *a, **k)  # type: ignore[misc]

    httpx.AsyncClient.__init__ = _async_init  # type: ignore[assignment]

    httpx._vw_no_verify_patch = True  # type: ignore[attr-defined]
