"""LDAP protocol message conversion; no application logic here."""

from typing import List, Optional

from ldapcoder.berutils import BERBase, BEROctetString, BERSequence, TagClasses
from ldapcoder.exceptions import UnknownTagError
from ldapcoder.ldaputils import LDAPOID, LDAPProtocolResponse, check
from ldapcoder.registry import PROTOCOL_OPERATIONS


class LDAPIntermediateResponse_responseName(LDAPOID):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00


class LDAPIntermediateResponse_responseValue(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x01


# IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
#         responseName     [0] LDAPOID OPTIONAL,
#         responseValue    [1] OCTET STRING OPTIONAL }
@PROTOCOL_OPERATIONS.add
class LDAPIntermediateResponse(LDAPProtocolResponse, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x19
    responseName: Optional[str]
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
                raise UnknownTagError(unknown_tag)
        return cls(responseName=responseName, responseValue=responseValue)

    def __init__(self, responseName: str = None, responseValue: bytes = None):
        self.responseName = responseName
        self.responseValue = responseValue

    def to_wire(self) -> bytes:
        ret: List[BERBase] = []
        if self.responseName is not None:
            ret.append(LDAPIntermediateResponse_responseName(self.responseName))
        if self.responseValue is not None:
            ret.append(LDAPIntermediateResponse_responseValue(self.responseValue))
        return self.wrap(ret)

    def __repr__(self) -> str:
        attributes = []
        if self.responseName:
            attributes.append(f"responseName={self.responseName!r}")
        if self.responseValue:
            attributes.append(f"responseValue={self.responseValue!r}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"
