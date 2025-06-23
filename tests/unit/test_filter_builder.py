import pytest

from vaultwarden_ldap_sync.filter_builder import build_ldap_filter


@pytest.mark.parametrize(
    "object_type,groups,additional,expected",
    [
        ("person", None, None, "(objectClass=person)"),
        ("*", None, None, "(objectClass=*)"),  # wildcard => default
        (None, "cn=test,dc=local", None, "(memberOf=cn=test,dc=local)"),
        (
            None,
            "cn=g1,dc=local, cn=g2,dc=local",
            None,
            "(|(memberOf=cn=g1,dc=local)(memberOf=cn=g2,dc=local))",
        ),
        (
            "person",
            "cn=g1,dc=local",
            "(uid=jdoe)",
            "(&(objectClass=person)(memberOf=cn=g1,dc=local)(uid=jdoe))",
        ),
        # No clauses at all => default match all
        (None, None, None, "(objectClass=*)"),
    ],
)
def test_build_filter(object_type, groups, additional, expected):
    assert build_ldap_filter(object_type, groups, additional) == expected


def test_invalid_group_attr():
    """Ensure custom group attribute is respected."""
    flt = build_ldap_filter(groups="cn=g,dc=local", group_attr="member")
    assert flt == "(member=cn=g,dc=local)"
