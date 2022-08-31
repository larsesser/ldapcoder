"""LDAP protocol message conversion; no application logic here."""

from ldapcoder.berutils import BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, DistinguishedName, LDAPAttributeValueAssertion, LDAPProtocolRequest, decode,
)
from ldapcoder.registry import PROTOCOL_OPERATIONS
from ldapcoder.result import LDAPResult


# CompareRequest ::= [APPLICATION 14] SEQUENCE {
#      entry           LDAPDN,
#      ava             AttributeValueAssertion }
@PROTOCOL_OPERATIONS.add
class LDAPCompareRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0E

    entry: DistinguishedName
    ava: LDAPAttributeValueAssertion

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPCompareRequest":
        vals = cls.unwrap(content)
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])
        entry = decode(vals[0], LDAPDN).dn
        ava = decode(vals[1], LDAPAttributeValueAssertion)
        return cls(entry=entry, ava=ava)

    def __init__(self, entry: DistinguishedName, ava: LDAPAttributeValueAssertion):
        self.entry = entry
        self.ava = ava

    def to_wire(self) -> bytes:
        return self.wrap([LDAPDN(self.entry), self.ava])

    def __repr__(self) -> str:
        attributes = [f"entry={self.entry}", f"ava={self.ava!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# CompareResponse ::= [APPLICATION 15] LDAPResult
@PROTOCOL_OPERATIONS.add
class LDAPCompareResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0F
