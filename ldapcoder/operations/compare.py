"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, LDAPAttributeValueAssertion, LDAPProtocolRequest, check, decode,
)
from ldapcoder.result import LDAPResult


# CompareRequest ::= [APPLICATION 14] SEQUENCE {
#      entry           LDAPDN,
#      ava             AttributeValueAssertion }
class LDAPCompareRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0E

    entry: str
    ava: LDAPAttributeValueAssertion

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPCompareRequest":
        vals = cls.unwrap(content)
        check(len(vals) == 2)
        entry = decode(vals[0], LDAPDN).value
        ava = decode(vals[1], LDAPAttributeValueAssertion)
        return cls(entry=entry, ava=ava)

    def __init__(self, entry: str, ava: LDAPAttributeValueAssertion):
        self.entry = entry
        self.ava = ava

    def to_wire(self) -> bytes:
        return self.wrap([LDAPDN(self.entry), self.ava])

    def __repr__(self) -> str:
        attributes = [f"entry={self.entry}", f"ava={self.ava!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# CompareResponse ::= [APPLICATION 15] LDAPResult
class LDAPCompareResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0F
