"""LDAP protocol message conversion; no application logic here."""

from typing import List

from ldapcoder.berutils import BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, LDAPAttribute, LDAPAttributeList, LDAPProtocolRequest, check, decode,
)
from ldapcoder.result import LDAPResult


# AddRequest ::= [APPLICATION 8] SEQUENCE {
#      entry           LDAPDN,
#      attributes      AttributeList }
class LDAPAddRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x08
    entry: str
    attributes: List[LDAPAttribute]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPAddRequest":
        vals = cls.unwrap(content)
        check(len(vals) == 2)
        entry = decode(vals[0], LDAPDN).value
        attributes = decode(vals[1], LDAPAttributeList).value
        return cls(entry=entry, attributes=attributes)

    def __init__(self, entry: str, attributes: List[LDAPAttribute]):
        self.entry = entry
        self.attributes = attributes

    def to_wire(self) -> bytes:
        return self.wrap([LDAPDN(self.entry), LDAPAttributeList(self.attributes)])

    def __repr__(self) -> str:
        attributes = [f"entry={self.entry}", f"attributes={self.attributes!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# AddResponse ::= [APPLICATION 9] LDAPResult
class LDAPAddResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x09
