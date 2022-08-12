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
