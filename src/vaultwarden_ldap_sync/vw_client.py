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
import asyncio
import logging

from vaultwarden.clients.bitwarden import BitwardenAPIClient as _BWClient
from vaultwarden.models.bitwarden import Organization, get_organization

# Set up logging
logger = logging.getLogger(__name__)


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
        
        if hasattr(exc, 'response') and exc.response is not None:
            response = exc.response
            details.append(f' [HTTP {response.status_code}]')
            
            # Try to extract response body safely
            response_body = self._safe_read_response_body(response)
            if response_body:
                details.append(f' Response: {response_body}')
        
        return ''.join(details)
    
    def _safe_read_response_body(self, response) -> str:
        """Extract response body content from httpx response.
        
        The python-vaultwarden library uses httpx internally. When errors occur,
        the response may be in streaming mode. The key insight is that we need to
        iterate over the stream to consume it before it gets closed.
        """
        try:
            # Strategy 1: Check if stream is available and not consumed
            if hasattr(response, 'stream') and not response.is_stream_consumed:
                try:
                    # Iterate the stream to get chunks before it's closed
                    chunks = list(response.stream)
                    if chunks:
                        content_bytes = b''.join(chunks)
                        content_text = content_bytes.decode('utf-8', errors='replace')
                        return self._parse_error_from_text(content_text)
                except Exception as err:
                    logger.debug("Stream iteration failed: %s", err)

            # Strategy 2: Try standard response.read() - works if stream=False
            try:
                content_bytes = response.read()
                if content_bytes:
                    content_text = content_bytes.decode('utf-8', errors='replace')
                    return self._parse_error_from_text(content_text)
            except Exception as err:
                logger.debug("response.read() failed: %s", err)

            # Strategy 3: Try response.content (may work if already read)
            try:
                content_bytes = response.content
                if content_bytes:
                    content_text = content_bytes.decode('utf-8', errors='replace')
                    return self._parse_error_from_text(content_text)
            except Exception as err:
                logger.debug("response.content failed: %s", err)

            # Strategy 4: Try response.text (may work if already read)
            try:
                text = response.text
                if text:
                    return self._parse_error_from_text(text)
            except Exception as err:
                logger.debug("response.text failed: %s", err)

            # Strategy 5: Try JSON extraction (may work if content is accessible)
            json_ct = response.headers.get("content-type", "").lower()
            if "application/json" in json_ct:
                try:
                    return self._extract_json_error_message(response)
                except Exception as err:
                    logger.debug("JSON extraction failed: %s", err)

            return "[Response body could not be accessed]"
        except Exception as e:
            logger.debug("Unhandled error in _safe_read_response_body: %s", e)
            return f"[Error reading response body: {type(e).__name__}]"
    
    def _parse_error_from_text(self, content_text: str) -> str:
        """Parse error message from response text content."""
        try:
            # Try to parse as JSON first
            if content_text.strip().startswith('{'):
                import json
                json_data = json.loads(content_text)
                return self._extract_message_from_json(json_data)
            else:
                # Return plain text content (truncated if too long)
                return content_text[:500] if len(content_text) <= 500 else content_text[:500] + '...'
        except (json.JSONDecodeError, ValueError):
            # Not valid JSON, return as text
            return content_text[:500] if len(content_text) <= 500 else content_text[:500] + '...'
    
    def _extract_message_from_json(self, json_data) -> str:
        """Extract the most relevant error message from VaultWarden's JSON structure."""
        if isinstance(json_data, dict):
            # Try to get the main error message
            if 'message' in json_data and json_data['message']:
                return json_data['message']
            # Try to get nested error message from errorModel
            elif 'errorModel' in json_data and isinstance(json_data['errorModel'], dict):
                if 'message' in json_data['errorModel'] and json_data['errorModel']['message']:
                    return json_data['errorModel']['message']
            # Try to get validation errors
            elif 'validationErrors' in json_data and isinstance(json_data['validationErrors'], dict):
                errors = []
                for field, field_errors in json_data['validationErrors'].items():
                    if isinstance(field_errors, list):
                        errors.extend(field_errors)
                if errors:
                    return '; '.join(errors)
            # Fallback to entire JSON if structure is unexpected but looks informative
            else:
                json_str = str(json_data)
                return json_str[:300] if len(json_str) <= 300 else json_str[:300] + '...'
        return str(json_data)[:300]
    
    def _extract_json_error_message(self, response) -> str:
        """Extract meaningful error message from VaultWarden JSON response."""
        try:
            json_data = response.json()
            return self._extract_message_from_json(json_data)
        except (ValueError, TypeError, AttributeError):
            # JSON parsing failed, try text
            pass
        
        # Fall back to text content
        try:
            if hasattr(response, 'text'):
                text_content = response.text
                if text_content:
                    return text_content[:500] if len(text_content) <= 500 else text_content[:500] + '...'
        except Exception:
            pass
            
        return '[Could not extract response content]'


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
