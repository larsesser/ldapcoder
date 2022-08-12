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


# DelRequest ::= [APPLICATION 10] LDAPDN
class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0A

    def __repr__(self):
        entry = self.value
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(entry=%s)" % repr(entry)
        else:
            return self.__class__.__name__ + "(entry=%s, tag=%d)" % (
                repr(entry),
                self.tag,
            )


# DelResponse ::= [APPLICATION 11] LDAPResult
class LDAPDelResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0B


class LDAPModifyDNResponse_newSuperior(LDAPDN):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00


# ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
#      entry           LDAPDN,
#      newrdn          RelativeLDAPDN,
#      deleteoldrdn    BOOLEAN,
#      newSuperior     [0] LDAPDN OPTIONAL }
class LDAPModifyDNRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0C

    entry: str
    newrdn: str
    deleteoldrdn: bool
    newSuperior: Optional[str]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPModifyDNRequest":
        vals = cls.unwrap(content)
        check(3 <= len(vals) <= 4)

        entry = decode(vals[0], LDAPDN).value
        newrdn = decode(vals[1], LDAPRelativeDN).value
        deleteoldrdn = decode(vals[2], BERBoolean).value
        newSuperior = None
        if len(vals) == 4:
            newSuperior = decode(vals[3], LDAPModifyDNResponse_newSuperior).value
        return cls(entry=entry, newrdn=newrdn, deleteoldrdn=deleteoldrdn, newSuperior=newSuperior)

    def __init__(self, entry: str, newrdn: str, deleteoldrdn: bool, newSuperior: str = None):
        self.entry = entry
        self.newrdn = newrdn
        self.deleteoldrdn = deleteoldrdn
        self.newSuperior = newSuperior

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPDN(self.entry), LDAPRelativeDN(self.newrdn), BERBoolean(self.deleteoldrdn)]
        if self.newSuperior is not None:
            ret.append(LDAPModifyDNResponse_newSuperior(self.newSuperior))
        return self.wrap(ret)

    def __repr__(self):
        l = [
            "entry=%s" % repr(self.entry),
            "newrdn=%s" % repr(self.newrdn),
            "deleteoldrdn=%s" % repr(self.deleteoldrdn),
        ]
        if self.newSuperior is not None:
            l.append("newSuperior=%s" % repr(self.newSuperior))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


# ModifyDNResponse ::= [APPLICATION 13] LDAPResult
class LDAPModifyDNResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0D


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


# AbandonRequest ::= [APPLICATION 16] MessageID
class LDAPAbandonRequest(LDAPProtocolRequest, LDAPMessageId):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x10
    needs_answer = 0

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(id=%s)" % repr(self.value)
        else:
            return self.__class__.__name__ + "(id=%s, tag=%d)" % (
                repr(self.value),
                self.tag,
            )


class LDAPIntermediateResponse_responseName(LDAPOID):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00


class LDAPIntermediateResponse_responseValue(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x01


# IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
#         responseName     [0] LDAPOID OPTIONAL,
#         responseValue    [1] OCTET STRING OPTIONAL }
class LDAPIntermediateResponse(LDAPProtocolResponse, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x19
    responseName: Optional[bytes]
    responseValue: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPIntermediateResponse":
        vals = cls.unwrap(content)
        check(0 <= len(vals) <= 2)

        responseName = None
        responseValue = None
        for unknown_tag, unkown_content in vals:
            if unknown_tag == LDAPIntermediateResponse_responseName.tag:
                if responseName is not None:
                    raise ValueError
                responseName = LDAPIntermediateResponse_responseName.from_wire(unkown_content).value
            elif unknown_tag == LDAPIntermediateResponse_responseValue.tag:
                if responseValue is not None:
                    raise ValueError
                responseValue = LDAPIntermediateResponse_responseValue.from_wire(unkown_content).value
            else:
                raise UnknownBERTag(unknown_tag)
        return cls(responseName=responseName, responseValue=responseValue)

    def __init__(self, responseName: bytes = None, responseValue: bytes = None):
        self.responseName = responseName
        self.responseValue = responseValue

    def to_wire(self) -> bytes:
        ret: List[BERBase] = []
        if self.responseName is not None:
            ret.append(LDAPIntermediateResponse_responseName(self.responseName))
        if self.responseValue is not None:
            ret.append(LDAPIntermediateResponse_responseValue(self.responseValue))
        return self.wrap(ret)
