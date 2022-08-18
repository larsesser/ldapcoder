"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import TagClasses
from ldapcoder.ldaputils import LDAPProtocolRequest, LDAPString
from ldapcoder.registry import PROTOCOL_OPERATIONS
from ldapcoder.result import LDAPResult


# DelRequest ::= [APPLICATION 10] LDAPDN
@PROTOCOL_OPERATIONS.add
class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0A


# DelResponse ::= [APPLICATION 11] LDAPResult
@PROTOCOL_OPERATIONS.add
class LDAPDelResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0B
