"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import TagClasses
from ldapcoder.ldaputils import LDAPProtocolRequest, LDAPString
from ldapcoder.registry import PROTOCOL_OPERATIONS
from ldapcoder.result import LDAPResult


# DelRequest ::= [APPLICATION 10] LDAPDN
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    """Delete an entry from the LDAP tree.

    Only leaf entries (entries without child entries) can be deleted with this operation.

    The server SHALL NOT dereference aliases while resolving the name of the target
    entry to be removed.
    """
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0A


# DelResponse ::= [APPLICATION 11] LDAPResult
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPDelResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0B
