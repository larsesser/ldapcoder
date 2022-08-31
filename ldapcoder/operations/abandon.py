"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import TagClasses
from ldapcoder.ldaputils import LDAPMessageId, LDAPProtocolRequest
from ldapcoder.registry import PROTOCOL_OPERATIONS


# AbandonRequest ::= [APPLICATION 16] MessageID
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPAbandonRequest(LDAPProtocolRequest, LDAPMessageId):
    """Request the server to abandon the operation with the corresponding message id.

    The server will send no response to this request, so the client can not know if
    the operation was abandoned successfully or not. The server MAY abandon the operation
    identified by the MessageID.

    Abandon, Bind, Unbind, and StartTLS operations cannot be abandoned.
    """
    _tag_class = TagClasses.APPLICATION
    _tag = 0x10
    needs_answer = 0
