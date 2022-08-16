"""LDAP protocol message conversion; no application logic here."""

from typing import List, Optional, Type

from ldapcoder.berutils import (
    BERBase, BEROctetString, BERSequence, TagClasses, UnknownBERTag,
)
from ldapcoder.ldaputils import (
    LDAPDN, LDAPOID, LDAPProtocolRequest, LDAPString, Registry, check, decode,
)
from ldapcoder.result import LDAPReferral, LDAPResult, LDAPResultCode, ResultCodes


class LDAPExtendedRequest_requestName(LDAPOID):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00


class LDAPExtendedRequest_requestValue(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x01


# ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
#      requestName      [0] LDAPOID,
#      requestValue     [1] OCTET STRING OPTIONAL }
class LDAPExtendedRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x17
    requestName: bytes
    requestValue: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPExtendedRequest":
        vals = cls.unwrap(content)
        check(1 <= len(vals) <= 2)
        requestName = decode(vals[0], LDAPExtendedRequest_requestName).value
        requestValue = None
        if len(vals) == 2:
            requestValue = decode(vals[1], LDAPExtendedRequest_requestValue).value
        return cls(requestName=requestName, requestValue=requestValue)

    def __init__(self, requestName: bytes, requestValue: bytes = None):
        self.requestName = requestName
        self.requestValue = requestValue

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPExtendedRequest_requestName(self.requestName)]
        if self.requestValue is not None:
            ret.append(LDAPExtendedRequest_requestValue(self.requestValue))
        return self.wrap(ret)


class ExtendedRequestRegistry(Registry[bytes, Type[LDAPExtendedRequest]]):
    def add(self, item: Type[LDAPExtendedRequest]) -> None:
        if item.requestName in self._items:
            raise RuntimeError
        self._items[item.requestName] = item


EXTENDED_REQUESTS = ExtendedRequestRegistry({})


class LDAPExtendedResponse_requestName(LDAPOID):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x0A


class LDAPExtendedResponse_requestValue(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x0B


# ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
#      COMPONENTS OF LDAPResult,
#      responseName     [10] LDAPOID OPTIONAL,
#      responseValue    [11] OCTET STRING OPTIONAL }
class LDAPExtendedResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x18
    responseName: Optional[bytes]
    responseValue: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPExtendedResponse":
        vals = cls.unwrap(content)
        check(3 <= len(vals) <= 6)

        resultCode = decode(vals[0], LDAPResultCode).value
        matchedDN = decode(vals[1], LDAPDN).value
        diagnosticMessage = decode(vals[2], LDAPString).value

        referral = None
        responseName = None
        responseValue = None
        for unknown_tag, unknown_content in vals[3:]:
            if unknown_tag == LDAPReferral.tag:
                if referral is not None:
                    raise ValueError
                referral = LDAPReferral.from_wire(unknown_content).value
            elif unknown_tag == LDAPExtendedResponse_requestName.tag:
                if responseName is not None:
                    raise ValueError
                responseName = LDAPExtendedResponse_requestName.from_wire(unknown_content).value
            elif unknown_tag == LDAPExtendedResponse_requestValue.tag:
                if responseValue is not None:
                    raise ValueError
                responseValue = LDAPExtendedResponse_requestValue.from_wire(unknown_content).value
            else:
                raise UnknownBERTag(unknown_tag)

        r = cls(
            resultCode=resultCode,
            matchedDN=matchedDN,
            diagnosticMessage=diagnosticMessage,
            referral=referral,
            responseName=responseName,
            responseValue=responseValue,
        )
        return r

    def __init__(
        self,
        resultCode: ResultCodes,
        matchedDN: str,
        diagnosticMessage: str,
        referral: List[str] = None,
        responseName: bytes = None,
        responseValue: bytes = None,
    ):
        super().__init__(
            resultCode=resultCode,
            matchedDN=matchedDN,
            diagnosticMessage=diagnosticMessage,
            referral=referral,
        )
        self.responseName = responseName
        self.responseValue = responseValue

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPResultCode(self.resultCode), LDAPDN(self.matchedDN),
                              LDAPString(self.diagnosticMessage)]
        if self.referral is not None:
            ret.append(LDAPReferral(self.referral))
        if self.responseName is not None:
            ret.append(LDAPExtendedResponse_requestName(self.responseName))
        if self.responseValue is not None:
            ret.append(LDAPExtendedResponse_requestValue(self.responseValue))
        return self.wrap(ret)


class ExtendedResponseRegistry(Registry[bytes, Type[LDAPExtendedResponse]]):
    def add(self, item: Type[LDAPExtendedResponse]) -> None:
        if item.responseName in self._items:
            raise RuntimeError
        if item.responseName is None:
            raise RuntimeError
        self._items[item.responseName] = item


EXTENDED_RESPONSES = ExtendedResponseRegistry({})
