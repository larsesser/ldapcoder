"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import BERNull, TagClasses
from ldapcoder.ldaputils import LDAPProtocolRequest
from ldapcoder.registry import PROTOCOL_OPERATIONS


# UnbindRequest ::= [APPLICATION 2] NULL
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPUnbindRequest(LDAPProtocolRequest, BERNull):
    """Terminate an LDAP session."""
    _tag_class = TagClasses.APPLICATION
    _tag = 0x02
    needs_answer = 0
