"""LDAP filter builder utility.

This module provides a single :func:`build_ldap_filter` function that constructs
RFC-4515 compliant LDAP search filters from individual criteria.

Specification (from architecture doc):

    * object_type – value for ``(objectClass=...)``. If ``"*"`` or falsy, the
      clause is omitted.
    * groups – comma-separated DN strings; generates OR list of
      ``(<group_attr>=group_dn)`` components.  If only one group is provided the
      OR wrapper is skipped.
    * additional_filter – custom raw filter string (e.g. ``(uid=jdoe)``)
    * group_attr – attribute used for membership, default ``memberOf``.

All provided sub-filters are combined with an ``&`` (logical AND).  If only a
single component exists it is returned as-is.  When *no* component is supplied
 ``(objectClass=*)`` is returned (equivalent to match all).
"""
from __future__ import annotations

from typing import Optional

__all__ = ["build_ldap_filter"]


def _normalize(val: str | None) -> str | None:
    """Return stripped value or ``None`` if empty/None."""
    if val is None:
        return None
    val = val.strip()
    return val or None


def build_ldap_filter(
    object_type: Optional[str] = None,
    groups: Optional[str] = None,
    additional_filter: Optional[str] = None,
    group_attr: str = "memberOf",
) -> str:
    """Construct an LDAP filter string from supplied components.

    Parameters
    ----------
    object_type: str | None
        Value for *objectClass* clause.  A value of "*" or ``None`` disables the
        clause (match any objectClass).
    groups: str | None
        Comma-separated list of group DNs.  Generates membership OR filter.
    additional_filter: str | None
        Raw filter string supplied by the user; used verbatim.
    group_attr: str
        Attribute name used for membership check.  Defaults to ``memberOf``.

    Returns
    -------
    str
        RFC-4515 compliant LDAP filter.
    """
    obj = _normalize(object_type)
    if obj == "*":  # explicit wildcard -> ignore
        obj = None

    grp = _normalize(groups)
    addl = _normalize(additional_filter)

    parts: list[str] = []

    # objectClass filter
    if obj:
        parts.append(f"(objectClass={obj})")

    # group membership filter
    if grp:
        # Split group list while preserving commas that are part of the DN.
        # We consider the delimiter to be either:
        #   * a semicolon `;`
        #   * a pipe `|`
        #   * a comma *followed by whitespace* (", ") – typical in env values
        # Internal commas in a DN are not followed by whitespace, so this
        # heuristic keeps DN integrity for common cases like
        # "cn=user,dc=example,dc=com, cn=other,dc=example,dc=com".
        import re

        group_list = re.split(r";|\||,\s+", grp)
        group_list = [g.strip() for g in group_list if g.strip()]
        if len(group_list) == 1:
            parts.append(f"({group_attr}={group_list[0]})")
        elif group_list:
            or_clause = "".join(f"({group_attr}={g})" for g in group_list)
            parts.append(f"(|{or_clause})")

    # additional user filter (assumed well-formed string)
    if addl:
        # ensure it is wrapped in parentheses
        if not addl.startswith("("):
            addl = f"({addl})"
        parts.append(addl)

    if not parts:
        # default match all
        return "(objectClass=*)"

    if len(parts) == 1:
        return parts[0]

    # combine with AND
    return f"(&{''.join(parts)})"
