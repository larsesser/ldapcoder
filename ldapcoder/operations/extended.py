"""LDAP protocol message conversion; no application logic here."""

from typing import Any, List, Optional

from ldapcoder.berutils import BERBase, BEROctetString, BERSequence, TagClasses
from ldapcoder.exceptions import DuplicateTagReceivedError
from ldapcoder.ldaputils import LDAPDN, LDAPOID, LDAPProtocolRequest, LDAPString, decode
from ldapcoder.registry import (
    EXTENDED_REQUESTS, EXTENDED_RESPONSES, PROTOCOL_OPERATIONS,
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
@PROTOCOL_OPERATIONS.add
class LDAPExtendedRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x17
    requestName: str
    requestValue: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPExtendedRequest":
        vals = cls.unwrap(content)
        if len(vals) < 1:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])
        requestName = decode(vals[0], LDAPExtendedRequest_requestName).value
        requestValue = None
        if len(vals) >= 2:
            requestValue = decode(vals[1], LDAPExtendedRequest_requestValue).value
        return cls(requestName=requestName, requestValue=requestValue)

    def __init__(self, requestName: str, requestValue: bytes = None):
        self.requestName = requestName
        self.requestValue = requestValue

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPExtendedRequest_requestName(self.requestName)]
        if self.requestValue is not None:
            ret.append(LDAPExtendedRequest_requestValue(self.requestValue))
        return self.wrap(ret)

    def __repr__(self) -> str:
        attributes = [f"requestName={self.requestName!r}"]
        if self.requestValue:
            attributes.append(f"requestValue={self.requestValue!r}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


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
@PROTOCOL_OPERATIONS.add
class LDAPExtendedResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x18
    responseName: Optional[str]
    responseValue: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPExtendedResponse":
        vals = cls.unwrap(content)
        if len(vals) < 3:
            cls.handle_missing_vals(vals)

        resultCode = decode(vals[0], LDAPResultCode).value
        matchedDN = decode(vals[1], LDAPDN).value
        diagnosticMessage = decode(vals[2], LDAPString).value

        referral = None
        responseName = None
        responseValue = None
        additional = []
        for unknown_tag, unknown_content in vals[3:]:
            if unknown_tag == LDAPReferral.tag:
                if referral is not None:
                    raise DuplicateTagReceivedError("referral")
                referral = LDAPReferral.from_wire(unknown_content).value
            elif unknown_tag == LDAPExtendedResponse_requestName.tag:
                if responseName is not None:
                    raise DuplicateTagReceivedError("responseName")
                responseName = LDAPExtendedResponse_requestName.from_wire(unknown_content).value
            elif unknown_tag == LDAPExtendedResponse_requestValue.tag:
                if responseValue is not None:
                    raise DuplicateTagReceivedError("responseValue")
                responseValue = LDAPExtendedResponse_requestValue.from_wire(unknown_content).value
            else:
                additional.append((unknown_tag, unknown_content))
        if additional:
            cls.handle_additional_vals(additional)

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
        responseName: str = None,
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

    def __repr__(self) -> str:
        attributes = [f"resultCode={self.resultCode!r}", f"matchedDN={self.matchedDN}",
                      f"diagnosticMessage={self.diagnosticMessage}"]
        if self.referral:
            attributes.append(f"referral={self.referral}")
        if self.responseName:
            attributes.append(f"responseName={self.responseName!r}")
        if self.responseValue:
            attributes.append(f"responseValue={self.responseValue!r}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


@EXTENDED_REQUESTS.add
class LDAPStartTLSRequest(LDAPExtendedRequest):
    requestName = "1.3.6.1.4.1.1466.20037"
    requestValue = None

    def __init__(self, **kwargs: Any):
        super().__init__(requestName=self.requestName, requestValue=self.requestValue)


@EXTENDED_RESPONSES.add
class LDAPStartTLSResponse(LDAPExtendedResponse):
    responseName = "1.3.6.1.4.1.1466.20037"
    responseValue = None

    def __init__(self, resultCode: ResultCodes, diagnosticMessage: str, **kwargs: Any):
        super().__init__(
            resultCode=resultCode,
            matchedDN="",
            diagnosticMessage=diagnosticMessage,
            referral=None,
            responseName=self.responseName,
            responseValue=self.responseValue
        )
