"""LDAP protocol message conversion; no application logic here."""
from typing import List, Optional

from ldapcoder.berutils import (
    BERBase, BERBoolean, BEROctetString, BERSequence, TagClasses,
)
from ldapcoder.exceptions import DuplicateTagReceivedError, UnknownTagError
from ldapcoder.ldaputils import LDAPOID, LDAPMessageId, LDAPProtocolOp, decode
from ldapcoder.operations.extended import LDAPExtendedRequest, LDAPExtendedResponse
from ldapcoder.operations.intermediate import LDAPIntermediateResponse
from ldapcoder.registry import (
    CONTROLS, EXTENDED_REQUESTS, EXTENDED_RESPONSES, INTERMEDIATE_RESPONSES,
    PROTOCOL_OPERATIONS,
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
# [RFC4511]
class LDAPMessage(BERSequence):
    """The envelope to send all LDAP operations over the network."""
    msg_id: int
    operation: "LDAPProtocolOp"
    controls: Optional[List["LDAPControl"]]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPMessage":
        vals = cls.unwrap(content)
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 3:
            cls.handle_additional_vals(vals[3:])

        msg_id = decode(vals[0], LDAPMessageId).message_id

        operation_tag, operation_content = vals[1]
        if operation_tag not in PROTOCOL_OPERATIONS:
            raise UnknownTagError(operation_tag)
        operation = PROTOCOL_OPERATIONS[operation_tag].from_wire(operation_content)
        # use special ExtendedRequest class if available
        if (isinstance(operation, LDAPExtendedRequest)
                and operation.requestName in EXTENDED_REQUESTS):
            operation = EXTENDED_REQUESTS[operation.requestName].from_wire(operation_content)
        # use special ExtendedResponse class if available
        elif (isinstance(operation, LDAPExtendedResponse)
                and operation.responseName is not None
                and operation.responseName in EXTENDED_RESPONSES):
            operation = EXTENDED_RESPONSES[operation.responseName].from_wire(operation_content)
        # use special IntermediateResponse class if available
        elif (isinstance(operation, LDAPIntermediateResponse)
              and operation.responseName is not None
              and operation.responseName in INTERMEDIATE_RESPONSES):
            operation = INTERMEDIATE_RESPONSES[operation.responseName].from_wire(operation_content)

        controls = None
        if len(vals) >= 3:
            controls = decode(vals[2], LDAPControls).controls

        r = cls(msg_id=msg_id, operation=operation, controls=controls)
        return r

    def __init__(self, msg_id: int, operation: "LDAPProtocolOp", controls: List["LDAPControl"] = None):
        self.msg_id = msg_id
        self.operation = operation
        self.controls = controls

    def to_wire(self) -> bytes:
        vals = [LDAPMessageId(self.msg_id), self.operation]
        if self.controls is not None:
            vals.append(LDAPControls(self.controls))
        return self.wrap(vals)

    def __repr__(self) -> str:
        attributes = [f"msg_id={self.msg_id}", f"operation={self.operation!r}"]
        if self.controls is not None:
            attributes.append(f"controls={self.controls!r}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# Controls ::= SEQUENCE OF control Control
# [RFC4511]
class LDAPControls(BERSequence):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00
    controls: List["LDAPControl"]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPControls":
        vals = cls.unwrap(content)
        controls: List[LDAPControl] = []
        for val in vals:
            control = decode(val, LDAPControl)
            if control.controlType in CONTROLS:
                control = decode(val, CONTROLS[control.controlType])
            controls.append(control)
        return cls(controls)

    def __init__(self, controls: List["LDAPControl"]):
        self.controls = controls

    def to_wire(self) -> bytes:
        return self.wrap(self.controls)

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(controls={self.controls!r})"


# Control ::= SEQUENCE {
#      controlType             LDAPOID,
#      criticality             BOOLEAN DEFAULT FALSE,
#      controlValue            OCTET STRING OPTIONAL }
# [RFC4511]
class LDAPControl(BERSequence):
    """Extend mechanism for arbitrary LDAPRequests and LDAPResponses.

    Controls are considered optional. Whether the server deems an unrecognized,
    unappropriated, or otherwise unfitting control for a given operation as an error
    is controlled by the criticality bool: If it's True, the server MUST NOT perform the
    operation and return a resultMessage with resultCode unavailableCriticalExtension.
    Otherwise, the server MUST ignore the control entirely.
    """
    controlType: str
    criticality: Optional[bool]
    controlValue: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPControl":
        vals = cls.unwrap(content)
        if len(vals) < 1:
            cls.handle_missing_vals(vals)

        controlType = decode(vals[0], LDAPOID).oid

        criticality = None
        controlValue = None
        additional = []
        for unknown_tag, unknown_content in vals[1:]:
            if unknown_tag == BERBoolean.tag:
                if criticality is not None:
                    # TODO this may lead to false-positive catches
                    raise DuplicateTagReceivedError("criticality")
                criticality = BERBoolean.from_wire(unknown_content).boolean
            elif unknown_tag == BEROctetString.tag:
                if controlValue is not None:
                    # TODO this may lead to false-positive catches
                    raise DuplicateTagReceivedError("controlValue")
                controlValue = BEROctetString.from_wire(unknown_content).bytes_
            else:
                additional.append((unknown_tag, unknown_content))
        if additional:
            cls.handle_additional_vals(additional)

        return cls(controlType=controlType, criticality=criticality, controlValue=controlValue)

    def __init__(
        self, controlType: str, criticality: bool = None, controlValue: bytes = None
    ):
        self.controlType = controlType
        self.criticality = criticality
        self.controlValue = controlValue

    def to_wire(self) -> bytes:
        vals: List[BERBase] = [LDAPOID(self.controlType)]
        if self.criticality is not None:
            vals.append(BERBoolean(self.criticality))
        if self.controlValue is not None:
            vals.append(BEROctetString(self.controlValue))
        return self.wrap(vals)

    def __repr__(self) -> str:
        attributes = [f"controlType={self.controlType}"]
        if self.criticality is not None:
            attributes.append(f"criticality={self.criticality}")
        if self.controlValue is not None:
            attributes.append(f"controlValue={self.controlValue!r}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"
