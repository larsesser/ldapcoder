"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import TagClasses
from ldapcoder.ldaputils import LDAPMessageId, LDAPProtocolRequest
from ldapcoder.registry import PROTOCOL_OPERATIONS


# AbandonRequest ::= [APPLICATION 16] MessageID
@PROTOCOL_OPERATIONS.add
class LDAPAbandonRequest(LDAPProtocolRequest, LDAPMessageId):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x10
    needs_answer = 0
