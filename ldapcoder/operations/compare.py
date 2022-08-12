"""LDAP protocol message conversion; no application logic here."""

import abc
import enum
import string
from typing import Optional, List, Mapping, Type, Union, Tuple, TypeVar

from ldapcoder.ldaputils import (
    alloc_ldap_message_id, escape, check, decode, LDAPString, LDAPDN, LDAPRelativeDN,
    LDAPURI, LDAPMessageId, LDAPProtocolOp, LDAPProtocolRequest, LDAPProtocolResponse,
    LDAPException, LDAPAttributeDescription, LDAPAssertionValue, LDAPAttributeValueAssertion,
    LDAPAttributeSelection, LDAPPartialAttribute, LDAPPartialAttributeList,
    LDAPAttribute, LDAPAttributeList, LDAPOID)
from ldapcoder.result import LDAPReferral, ResultCodes, LDAPResultCode, LDAPResult

from ldaptor.protocols.pureber import (
    BERBoolean,
    BEREnumerated,
    BERInteger,
    BERNull,
    BEROctetString,
    BERSequence,
    BERSet,
    int2berlen,
    UnknownBERTag,
    BERBase,
    TagClasses,
    ber_unwrap,
)


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

    def __repr__(self):
        l = [
            f"entry={repr(self.entry)}",
            f"ava={repr(self.ava)}",
        ]
        return "{}({})".format(self.__class__.__name__, ", ".join(l))


# CompareResponse ::= [APPLICATION 15] LDAPResult
class LDAPCompareResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0F
