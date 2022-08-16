"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import TagClasses
from ldapcoder.ldaputils import LDAPProtocolRequest, LDAPString
from ldapcoder.result import LDAPResult


# DelRequest ::= [APPLICATION 10] LDAPDN
class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0A


# DelResponse ::= [APPLICATION 11] LDAPResult
class LDAPDelResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0B
