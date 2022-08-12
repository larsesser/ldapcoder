"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import BERNull, TagClasses
from ldapcoder.ldaputils import LDAPProtocolRequest


# UnbindRequest ::= [APPLICATION 2] NULL
class LDAPUnbindRequest(LDAPProtocolRequest, BERNull):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x02
    needs_answer = 0
