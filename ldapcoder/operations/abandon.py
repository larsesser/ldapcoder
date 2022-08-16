"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import TagClasses
from ldapcoder.ldaputils import LDAPMessageId, LDAPProtocolRequest


# AbandonRequest ::= [APPLICATION 16] MessageID
class LDAPAbandonRequest(LDAPProtocolRequest, LDAPMessageId):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x10
    needs_answer = 0
