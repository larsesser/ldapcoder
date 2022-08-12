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


# LDAPMessage ::= SEQUENCE {
#      messageID       MessageID,
#      protocolOp      CHOICE {
#           bindRequest           BindRequest,
#           bindResponse          BindResponse,
#           unbindRequest         UnbindRequest,
#           searchRequest         SearchRequest,
#           searchResEntry        SearchResultEntry,
#           searchResDone         SearchResultDone,
#           searchResRef          SearchResultReference,
#           modifyRequest         ModifyRequest,
#           modifyResponse        ModifyResponse,
#           addRequest            AddRequest,
#           addResponse           AddResponse,
#           delRequest            DelRequest,
#           delResponse           DelResponse,
#           modDNRequest          ModifyDNRequest,
#           modDNResponse         ModifyDNResponse,
#           compareRequest        CompareRequest,
#           compareResponse       CompareResponse,
#           abandonRequest        AbandonRequest,
#           extendedReq           ExtendedRequest,
#           extendedResp          ExtendedResponse,
#           ...,
#           intermediateResponse  IntermediateResponse },
#      controls       [0] Controls OPTIONAL }
class LDAPMessage(BERSequence):
    """
    To encode this object in order to be sent over the network use the to_wire()
    method.
    """
    msg_id: int
    operation: "LDAPProtocolOp"
    controls: Optional[List["LDAPControl"]]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPMessage":
        vals = cls.unwrap(content)
        check(len(vals) in {2, 3})

        msg_id = decode(vals[0], LDAPMessageId).value

        operation_tag, operation_content = vals[1]
        if operation_tag not in PROTOCOL_OPERATIONS:
            raise UnknownBERTag(operation_tag)
        operation = PROTOCOL_OPERATIONS[operation_tag].from_wire(operation_content)
        assert isinstance(operation, LDAPProtocolOp)

        controls = None
        if len(vals) == 3:
            controls = decode(vals[2], LDAPControls).controls

        r = cls(msg_id=msg_id, operation=operation, controls=controls)
        return r

    def __init__(self, operation: "LDAPProtocolOp", controls: List["LDAPControl"] = None, msg_id: int = None):
        if msg_id is None:
            msg_id = alloc_ldap_message_id()
        self.msg_id = msg_id
        self.operation = operation
        self.controls = controls

    def to_wire(self) -> bytes:
        vals = [LDAPMessageId(self.msg_id), self.operation]
        if self.controls is not None:
            vals.append(LDAPControls(self.controls))
        return self.wrap(vals)

    def __repr__(self):
        l = []
        l.append("id=%r" % self.msg_id)
        l.append("value=%r" % self.operation)
        l.append("controls=%r" % self.controls)
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


# Controls ::= SEQUENCE OF control Control
class LDAPControls(BERSequence):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00
    controls: List["LDAPControl"]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPControls":
        vals = cls.unwrap(content)
        controls = [decode(val, LDAPControl) for val in vals]
        return cls(controls)

    def __init__(self, controls: List["LDAPControl"]):
        self.controls = controls

    def to_wire(self) -> bytes:
        return self.wrap(self.controls)


# Control ::= SEQUENCE {
#      controlType             LDAPOID,
#      criticality             BOOLEAN DEFAULT FALSE,
#      controlValue            OCTET STRING OPTIONAL }
class LDAPControl(BERSequence):
    controlType: bytes
    criticality: Optional[bool]
    controlValue: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPControl":
        vals = cls.unwrap(content)
        check(1 <= len(vals) <= 3)

        controlType = decode(vals[0], LDAPOID).value

        criticality = None
        controlValue = None
        if len(vals) == 2:
            unknown_tag, _ = vals[1]
            if unknown_tag == BERBoolean.tag:
                criticality = decode(vals[1], BERBoolean).value
            elif unknown_tag == BEROctetString.tag:
                controlValue = decode(vals[1], BEROctetString).value
            else:
                raise UnknownBERTag(unknown_tag)
        elif len(vals) == 3:
            criticality = decode(vals[1], BERBoolean).value
            controlValue = decode(vals[2], BEROctetString).value

        return cls(controlType=controlType, criticality=criticality, controlValue=controlValue)

    def __init__(
        self, controlType: bytes, criticality: bool = None, controlValue: bytes = None
    ):
        self.controlType = controlType
        self.criticality = criticality
        self.controlValue = controlValue

    def to_wire(self):
        vals = [LDAPOID(self.controlType)]
        if self.criticality is not None:
            vals.append(BERBoolean(self.criticality))
        if self.controlValue is not None:
            vals.append(BEROctetString(self.controlValue))
        return self.wrap(vals)

    def __repr__(self):
        criticality = str(self.criticality) if self.criticality is not None else "Default"
        return (f"{self.__class__.__name__}(controlType={self.controlType},"
                f" criticality={criticality}, controlValue={self.controlValue})")


PROTOCOL_OPERATIONS: Mapping[int, Type[LDAPProtocolOp]] = {
    LDAPBindResponse.tag: LDAPBindResponse,
    LDAPBindRequest.tag: LDAPBindRequest,
    LDAPUnbindRequest.tag: LDAPUnbindRequest,
    LDAPSearchRequest.tag: LDAPSearchRequest,
    LDAPSearchResultEntry.tag: LDAPSearchResultEntry,
    LDAPSearchResultDone.tag: LDAPSearchResultDone,
    LDAPSearchResultReference.tag: LDAPSearchResultReference,
    LDAPModifyRequest.tag: LDAPModifyRequest,
    LDAPModifyResponse.tag: LDAPModifyResponse,
    LDAPAddRequest.tag: LDAPAddRequest,
    LDAPAddResponse.tag: LDAPAddResponse,
    LDAPDelRequest.tag: LDAPDelRequest,
    LDAPDelResponse.tag: LDAPDelResponse,
    LDAPExtendedRequest.tag: LDAPExtendedRequest,
    LDAPExtendedResponse.tag: LDAPExtendedResponse,
    LDAPModifyDNRequest.tag: LDAPModifyDNRequest,
    LDAPModifyDNResponse.tag: LDAPModifyDNResponse,
    LDAPAbandonRequest.tag: LDAPAbandonRequest,
    LDAPCompareRequest.tag: LDAPCompareRequest,
    LDAPCompareResponse.tag: LDAPCompareResponse,
}