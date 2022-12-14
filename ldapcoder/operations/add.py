"""LDAP protocol message conversion; no application logic here."""

from typing import List

from ldapcoder.berutils import BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, DistinguishedName, LDAPAttribute, LDAPAttributeList, LDAPProtocolRequest,
    decode,
)
from ldapcoder.registry import PROTOCOL_OPERATIONS
from ldapcoder.result import LDAPResult


# AddRequest ::= [APPLICATION 8] SEQUENCE {
#      entry           LDAPDN,
#      attributes      AttributeList }
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPAddRequest(LDAPProtocolRequest, BERSequence):
    """Add a new entry to the LDAP tree.

    The server MUST ensure that the entry conform to user and system schema rules or
    other data model constraints.

    The entry MUST NOT exist and the parent entry MUST exist, otherwise the AddRequest
    will fail.

    The server SHALL NOT dereference any aliases in locating the entry to be added.
    """
    _tag_class = TagClasses.APPLICATION
    _tag = 0x08
    entry: DistinguishedName
    attributes: List[LDAPAttribute]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPAddRequest":
        vals = cls.unwrap(content)
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])
        entry = decode(vals[0], LDAPDN).dn
        attributes = decode(vals[1], LDAPAttributeList).attributes
        return cls(entry=entry, attributes=attributes)

    def __init__(self, entry: DistinguishedName, attributes: List[LDAPAttribute]):
        self.entry = entry
        self.attributes = attributes

    def to_wire(self) -> bytes:
        return self.wrap([LDAPDN(self.entry), LDAPAttributeList(self.attributes)])

    def __repr__(self) -> str:
        attributes = [f"entry={self.entry}", f"attributes={self.attributes!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# AddResponse ::= [APPLICATION 9] LDAPResult
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPAddResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x09
