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


# AuthenticationChoice ::= CHOICE {
#      simple                  [0] OCTET STRING,
#                -- 1 and 2 reserved
#      sasl                    [3] SaslCredentials,
#      ...  }
class LDAPBindRequest_SimpleAuthentication(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00


# SaslCredentials ::= SEQUENCE {
#      mechanism               LDAPString,
#      credentials             OCTET STRING OPTIONAL }
class LDAPBindRequest_SaslAuthentication(BERSequence):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x03
    mechanism: str
    credentials: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindRequest_SaslAuthentication":
        vals = cls.unwrap(content)
        check(len(vals) in {1, 2})

        mechanism = decode(vals[0], LDAPString).value
        # per https://ldap.com/ldapv3-wire-protocol-reference-bind/
        # Credentials are optional and not always provided
        if len(vals) == 1:
            return cls(mechanism=mechanism, credentials=None)

        credentials = decode(vals[1], BEROctetString).value
        return cls(mechanism=mechanism, credentials=credentials)

    def __init__(self, mechanism: str, credentials: bytes = None):
        self.mechanism = mechanism
        self.credentials = credentials

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPString(self.mechanism)]
        if self.credentials:
            ret.append(BEROctetString(self.credentials))
        return self.wrap(ret)


# BindRequest ::= [APPLICATION 0] SEQUENCE {
#      version                 INTEGER (1 ..  127),
#      name                    LDAPDN,
#      authentication          AuthenticationChoice }
class LDAPBindRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x00
    version: int
    dn: str
    auth: Union[bytes, Tuple[str, Optional[bytes]]]
    sasl: bool

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindRequest":
        vals = cls.unwrap(content)
        check(len(vals) == 3)

        version = decode(vals[0], BERInteger).value
        dn = decode(vals[1], LDAPDN).value

        auth_tag, auth_content = vals[2]
        auth: Union[bytes, Tuple[str, Optional[bytes]]]
        if auth_tag == LDAPBindRequest_SimpleAuthentication.tag:
            auth = LDAPBindRequest_SimpleAuthentication.from_wire(auth_content).value
        elif auth_tag == LDAPBindRequest_SaslAuthentication.tag:
            auth_ = LDAPBindRequest_SaslAuthentication.from_wire(auth_content)
            auth = (auth_.mechanism, auth_.credentials)
        else:
            raise ValueError

        r = cls(version=version, dn=dn, auth=auth)
        return r

    def __init__(self, version: int, dn: str,
                 auth: Union[bytes, Tuple[str, Optional[bytes]]]):
        """Constructor for LDAP Bind Request

        For sasl=False, pass a string password for 'auth'
        For sasl=True, pass a tuple of (mechanism, credentials) for 'auth'"""
        self.version = version
        self.dn = dn
        self.auth = auth
        if isinstance(auth, bytes):
            sasl = False
        elif isinstance(auth, tuple):
            sasl = True
        else:
            raise ValueError
        self.sasl = sasl

    def to_wire(self) -> bytes:
        auth: Union[LDAPBindRequest_SaslAuthentication, LDAPBindRequest_SimpleAuthentication]
        if self.sasl:
            assert isinstance(self.auth, tuple)
            # since the credentails for SASL is optional must check first
            # if credentials are None don't send them.
            mechanism = self.auth[0]
            credentials = self.auth[1] if len(self.auth) > 1 else None
            auth = LDAPBindRequest_SaslAuthentication(
                mechanism=mechanism, credentials=credentials)
        else:
            assert isinstance(self.auth, bytes)
            auth = LDAPBindRequest_SimpleAuthentication(self.auth)
        return self.wrap([BERInteger(self.version), LDAPDN(self.dn), auth])

    def __repr__(self):
        auth = "*" * len(self.auth)
        l = []
        l.append("version=%d" % self.version)
        l.append("dn=%s" % repr(self.dn))
        l.append("auth=%s" % repr(auth))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        l.append("sasl=%s" % repr(self.sasl))
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBindResponse_serverSaslCreds(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x07

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % self.value
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                self.value,
                self.tag,
            )


# BindResponse ::= [APPLICATION 1] SEQUENCE {
#      COMPONENTS OF LDAPResult,
#      serverSaslCreds    [7] OCTET STRING OPTIONAL }
class LDAPBindResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x01
    serverSaslCreds: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindResponse":
        vals = cls.unwrap(content)
        check(3 <= len(vals) <= 5)

        resultCode = decode(vals[0], LDAPResultCode).value
        matchedDN = decode(vals[1], LDAPDN).value
        diagnosticMessage = decode(vals[2], LDAPString).value

        referral = None
        serverSaslCreds = None
        if len(vals) == 4:
            unknown_tag, unknown_content = vals[3]
            if unknown_tag == LDAPReferral.tag:
                referral = decode(vals[3], LDAPReferral).value
            elif unknown_tag == LDAPBindResponse_serverSaslCreds.tag:
                serverSaslCreds = decode(vals[3], LDAPBindResponse_serverSaslCreds).value
            else:
                raise UnknownBERTag(unknown_tag)
        elif len(vals) == 5:
            referral = decode(vals[3], LDAPReferral).value
            serverSaslCreds = decode(vals[4], LDAPBindResponse_serverSaslCreds).value

        r = cls(
            resultCode=resultCode,
            matchedDN=matchedDN,
            diagnosticMessage=diagnosticMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
        )
        return r

    def __init__(
        self,
        resultCode: ResultCodes,
        matchedDN: str,
        diagnosticMessage: str,
        referral: List[str] = None,
        serverSaslCreds: bytes = None,
    ):
        super().__init__(resultCode, matchedDN, diagnosticMessage, referral)
        self.serverSaslCreds = serverSaslCreds

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPResultCode(self.resultCode), LDAPDN(self.matchedDN),
                              LDAPString(self.diagnosticMessage)]
        if self.referral is not None:
            ret.append(LDAPReferral(self.referral))
        if self.serverSaslCreds is not None:
            ret.append(LDAPBindResponse_serverSaslCreds(self.serverSaslCreds))
        return self.wrap(ret)

    def __repr__(self):
        return LDAPResult.__repr__(self)


# UnbindRequest ::= [APPLICATION 2] NULL
class LDAPUnbindRequest(LDAPProtocolRequest, BERNull):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x02
    needs_answer = 0


# Filter ::= CHOICE {
#      and             [0] SET SIZE (1..MAX) OF filter Filter,
#      or              [1] SET SIZE (1..MAX) OF filter Filter,
#      not             [2] Filter,
#      equalityMatch   [3] AttributeValueAssertion,
#      substrings      [4] SubstringFilter,
#      greaterOrEqual  [5] AttributeValueAssertion,
#      lessOrEqual     [6] AttributeValueAssertion,
#      present         [7] AttributeDescription,
#      approxMatch     [8] AttributeValueAssertion,
#      extensibleMatch [9] MatchingRuleAssertion,
#      ...  }
class LDAPFilter(BERBase, metaclass=abc.ABCMeta):
    _tag_class = TagClasses.CONTEXT

    @property
    @abc.abstractmethod
    def as_text(self) -> str:
        raise NotImplementedError


class LDAPFilterSet(BERSet, LDAPFilter, metaclass=abc.ABCMeta):
    filters: List[LDAPFilter]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPFilterSet":
        vals = cls.unwrap(content)
        filters = []
        for filter_tag, filter_content in vals:
            if filter_tag not in FILTERS:
                raise UnknownBERTag(filter_tag)
            filters.append(FILTERS[filter_tag].from_wire(filter_content))
        # the from_wire method returns BERBase objects, but we know they are LDAPFilters
        return cls(filters)  # type: ignore

    def __init__(self, filters: List[LDAPFilter]):
        self.filters = filters

    def __eq__(self, rhs):
        if not isinstance(rhs, LDAPFilterSet):
            return False

        if self is rhs:
            return True
        elif len(self) != len(rhs):
            return False

        return sorted(self.filters, key=lambda x: x.to_wire()) == sorted(
            rhs.filters, key=lambda x: x.to_wire()
        )

    def to_wire(self) -> bytes:
        return self.wrap(self.filters)


class LDAPFilter_and(LDAPFilterSet):
    _tag = 0x00

    @property
    def as_text(self) -> str:
        return "(&" + "".join([x.as_text for x in self.filters]) + ")"


class LDAPFilter_or(LDAPFilterSet):
    _tag = 0x01

    @property
    def as_text(self) -> str:
        return "(|" + "".join([x.as_text for x in self.filters]) + ")"


class LDAPFilter_not(LDAPFilter):
    _tag = 0x02
    value: LDAPFilter

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPFilter_not":
        [val], bytes_used = ber_unwrap(content)
        check(bytes_used == len(content))

        filter_tag, filter_content = val
        if filter_tag not in FILTERS:
            raise UnknownBERTag(filter_tag)
        value = FILTERS[filter_tag].from_wire(filter_content)
        # the from_wire method returns BERBase objects, but we know they are LDAPFilters
        return cls(value)  # type: ignore

    def __init__(self, value: LDAPFilter):
        self.value = value

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(self.value)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(self.value),
                self.tag,
            )

    def to_wire(self) -> bytes:
        value_bytes = self.value.to_wire()
        return bytes((self.tag,)) + int2berlen(len(value_bytes)) + value_bytes

    @property
    def as_text(self) -> str:
        return "(!" + self.value.as_text + ")"


class LDAPFilter_equalityMatch(LDAPAttributeValueAssertion, LDAPFilter):
    _tag = 0x03

    @property
    def as_text(self) -> str:
        return (
            "("
            + self.attributeDesc
            + "="
            # TODO is this assumption reasonable? Same question for the following cases.
            + escape(self.assertionValue.decode("utf-8"))
            + ")"
        )


class LDAPFilter_substrings_string(LDAPAssertionValue):
    _tag_class = TagClasses.CONTEXT

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPFilter_substrings_string":
        return super().from_wire(content)  # type: ignore

    @property
    def as_text(self) -> str:
        return escape(self.value.decode("utf-8"))


class LDAPFilter_substrings_initial(LDAPFilter_substrings_string):
    _tag = 0x00


class LDAPFilter_substrings_any(LDAPFilter_substrings_string):
    _tag = 0x01


class LDAPFilter_substrings_final(LDAPFilter_substrings_string):
    _tag = 0x02


class LDAP_substrings(BERSequence):
    value: List[LDAPFilter_substrings_string]

    @classmethod
    def from_wire(cls, content: bytes) -> "BERBase":
        vals = cls.unwrap(content)
        check(len(vals) != 0)

        substrings = []
        for substring_tag, substring_content in vals:
            if substring_tag == LDAPFilter_substrings_initial.tag:
                substring = LDAPFilter_substrings_initial.from_wire(substring_content)
            elif substring_tag == LDAPFilter_substrings_any.tag:
                substring = LDAPFilter_substrings_any.from_wire(substring_content)
            elif substring_tag == LDAPFilter_substrings_final.tag:
                substring = LDAPFilter_substrings_final.from_wire(substring_content)
            else:
                raise UnknownBERTag(substring_tag)
            substrings.append(substring)
        return cls(value=substrings)

    def __init__(self, value: List[LDAPFilter_substrings_string]):
        if sum(1 for substring in value if type(substring) is LDAPFilter_substrings_initial) > 1:
            raise ValueError
        if sum(1 for substring in value if type(substring) is LDAPFilter_substrings_final) > 1:
            raise ValueError
        self.value = value

    def to_wire(self) -> bytes:
        return self.wrap(self.value)


# SubstringFilter ::= SEQUENCE {
#      type           AttributeDescription,
#      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
#           initial [0] AssertionValue,  -- can occur at most once
#           any     [1] AssertionValue,
#           final   [2] AssertionValue } -- can occur at most once
#      }
class LDAPFilter_substrings(BERSequence, LDAPFilter):
    _tag = 0x04
    type: str
    substrings: List[LDAPFilter_substrings_string]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPFilter_substrings":
        vals = cls.unwrap(content)
        check(len(vals) == 2)

        type_ = decode(vals[0], LDAPAttributeDescription).value
        substrings = decode(vals[0], LDAP_substrings).value
        return cls(type_=type_, substrings=substrings)

    def __init__(self, type_: str, substrings: List[LDAPFilter_substrings_string]):
        self.type = type_
        # do validation
        self.substrings = LDAP_substrings(substrings).value

    def to_wire(self) -> bytes:
        return self.wrap([LDAPAttributeDescription(self.type), LDAP_substrings(self.substrings)])

    def __repr__(self):
        tp = self.type
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(type={}, substrings={})".format(
                repr(tp),
                repr(self.substrings),
            )
        else:
            return self.__class__.__name__ + "(type=%s, substrings=%s, tag=%d)" % (
                repr(tp),
                repr(self.substrings),
                self.tag,
            )

    @property
    def as_text(self) -> str:
        initial = None
        final = None
        any: List[str] = []

        for s in self.substrings:
            assert s is not None
            if isinstance(s, LDAPFilter_substrings_initial):
                assert initial is None
                assert not any
                assert final is None
                initial = s.as_text
            elif isinstance(s, LDAPFilter_substrings_final):
                assert final is None
                final = s.as_text
            elif isinstance(s, LDAPFilter_substrings_any):
                assert final is None
                any.append(s.as_text)
            else:
                raise NotImplementedError("TODO: Filter type not supported %r" % s)

        if initial is None:
            initial = ""
        if final is None:
            final = ""

        return "(" + self.type + "=" + "*".join([initial] + any + [final]) + ")"


class LDAPFilter_greaterOrEqual(LDAPAttributeValueAssertion, LDAPFilter):
    _tag = 0x05

    @property
    def as_text(self) -> str:
        return (
            "("
            + self.attributeDesc
            + ">="
            + escape(self.assertionValue.decode("utf-8"))
            + ")"
        )


class LDAPFilter_lessOrEqual(LDAPAttributeValueAssertion, LDAPFilter):
    _tag = 0x06

    @property
    def as_text(self) -> str:
        return (
            "("
            + self.attributeDesc
            + "<="
            + escape(self.assertionValue.decode("utf-8"))
            + ")"
        )


class LDAPFilter_present(LDAPAttributeDescription, LDAPFilter):
    _tag = 0x07

    @property
    def as_text(self) -> str:
        return "(" + self.value + "=*)"


class LDAPFilter_approxMatch(LDAPAttributeValueAssertion, LDAPFilter):
    _tag = 0x08

    @property
    def as_text(self) -> str:
        return (
            "("
            + self.attributeDesc
            + "~="
            + escape(self.assertionValue.decode("utf-8"))
            + ")"
        )


# MatchingRuleId ::= LDAPString
class LDAPMatchingRuleId(LDAPString):
    pass


class LDAPMatchingRuleAssertion_matchingRule(LDAPMatchingRuleId):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x01


class LDAPMatchingRuleAssertion_type(LDAPAttributeDescription):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x02


class LDAPMatchingRuleAssertion_matchValue(LDAPAssertionValue):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x03


class LDAPMatchingRuleAssertion_dnAttributes(BERBoolean):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x04


# MatchingRuleAssertion ::= SEQUENCE {
#      matchingRule    [1] MatchingRuleId OPTIONAL,
#      type            [2] AttributeDescription OPTIONAL,
#      matchValue      [3] AssertionValue,
#      dnAttributes    [4] BOOLEAN DEFAULT FALSE }
class LDAPMatchingRuleAssertion(BERSequence):
    matchingRule: Optional[str]
    type: Optional[str]
    matchValue: bytes
    dnAttributes: Optional[bool]  # None signals default value of False

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPMatchingRuleAssertion":
        vals = cls.unwrap(content)
        check(1 <= len(vals) <= 4)

        matchingRule = None
        type_ = None
        matchValue = None
        dnAttributes = None

        for unknown_tag, unknown_content in vals:
            if unknown_tag == LDAPMatchingRuleAssertion_matchingRule.tag:
                if matchingRule is not None:
                    raise ValueError
                matchingRule = LDAPMatchingRuleAssertion_matchingRule.from_wire(unknown_content).value
            elif unknown_tag == LDAPMatchingRuleAssertion_type.tag:
                if type_ is not None:
                    raise ValueError
                type_ = LDAPMatchingRuleAssertion_type.from_wire(unknown_content).value
            elif unknown_tag == LDAPMatchingRuleAssertion_matchValue.tag:
                if matchValue is not None:
                    raise ValueError
                matchValue = LDAPMatchingRuleAssertion_matchValue.from_wire(unknown_content).value
            elif unknown_tag == LDAPMatchingRuleAssertion_dnAttributes.tag:
                if dnAttributes is not None:
                    raise ValueError
                dnAttributes = LDAPMatchingRuleAssertion_dnAttributes.from_wire(unknown_content).value
            else:
                raise UnknownBERTag(unknown_tag)

        assert matchValue is not None
        return cls(matchingRule=matchingRule, type_=type_, matchValue=matchValue, dnAttributes=dnAttributes)

    def __init__(
        self,
        matchValue: bytes,
        matchingRule: str = None,
        type_: str = None,
        dnAttributes: bool = None,
    ):
        self.matchingRule = matchingRule
        self.type = type_
        self.matchValue = matchValue
        self.dnAttributes = dnAttributes

    def to_wire(self) -> bytes:
        to_send: List[BERBase] = []
        if self.matchingRule is not None:
            to_send.append(LDAPMatchingRuleAssertion_matchingRule(self.matchingRule))
        if self.type is not None:
            to_send.append(LDAPMatchingRuleAssertion_type(self.type))
        to_send.append(LDAPAssertionValue(self.matchValue))
        if self.dnAttributes is not None:
            to_send.append(LDAPMatchingRuleAssertion_dnAttributes(self.dnAttributes))
        return self.wrap(to_send)

    def __repr__(self):
        l = []
        l.append("matchingRule=%s" % repr(self.matchingRule))
        l.append("type=%s" % repr(self.type))
        l.append("matchValue=%s" % repr(self.matchValue))
        l.append("dnAttributes=%s" % repr(self.dnAttributes))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPFilter_extensibleMatch(LDAPMatchingRuleAssertion, LDAPFilter):
    _tag = 0x09

    @property
    def as_text(self) -> str:
        return (
            "("
            + (self.type if self.type else "")
            + (":dn" if self.dnAttributes and self.dnAttributes else "")
            + ((":" + self.matchingRule) if self.matchingRule else "")
            + ":="
            + escape(self.matchValue.decode("utf-8"))
            + ")"
        )


class SearchScopes(enum.IntEnum):
    baseObject = 0
    singleLevel = 1
    wholeSubtree = 2


class LDAPSearchScope(BEREnumerated):
    value: SearchScopes

    @classmethod
    def enum_cls(cls) -> Type[enum.IntEnum]:
        return SearchScopes


class DerefAliases(enum.IntEnum):
    neverDerefAliases = 0
    derefInSearching = 1
    derefFindingBaseObj = 2
    derefAlways = 3


class LDAPDerefAlias(BEREnumerated):
    value: DerefAliases

    @classmethod
    def enum_cls(cls) -> Type[enum.IntEnum]:
        return DerefAliases


# SearchRequest ::= [APPLICATION 3] SEQUENCE {
#      baseObject      LDAPDN,
#      scope           ENUMERATED {
#           baseObject              (0),
#           singleLevel             (1),
#           wholeSubtree            (2),
#           ...  },
#      derefAliases    ENUMERATED {
#           neverDerefAliases       (0),
#           derefInSearching        (1),
#           derefFindingBaseObj     (2),
#           derefAlways             (3) },
#      sizeLimit       INTEGER (0 ..  maxInt),
#      timeLimit       INTEGER (0 ..  maxInt),
#      typesOnly       BOOLEAN,
#      filter          Filter,
#      attributes      AttributeSelection }
class LDAPSearchRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x03

    baseObject: str
    scope: SearchScopes
    derefAliases: DerefAliases
    sizeLimit: int
    timeLimit: int
    typesOnly: bool
    filter: LDAPFilter
    attributes: List[str]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPSearchRequest":
        vals = cls.unwrap(content)
        check(len(vals) == 8)

        baseObject = decode(vals[0], LDAPDN).value
        scope = decode(vals[1], LDAPSearchScope).value
        derefAlias = decode(vals[2], LDAPDerefAlias).value
        sizeLimit = decode(vals[3], BERInteger).value
        timeLimit = decode(vals[4], BERInteger).value
        typesOnly = decode(vals[5], BERBoolean).value
        filter_tag, filter_content = vals[6]
        if filter_tag not in FILTERS:
            raise UnknownBERTag(filter_tag)
        # the from_wire method returns BERBase objects, but we know they are LDAPFilters
        filter_ = FILTERS[filter_tag].from_wire(filter_content)
        attributes = decode(vals[7], LDAPAttributeSelection).value

        return cls(
            baseObject=baseObject,
            scope=scope,
            derefAliases=derefAlias,
            sizeLimit=sizeLimit,
            timeLimit=timeLimit,
            typesOnly=typesOnly,
            filter_=filter_,  # type: ignore
            attributes=attributes,
        )

    def __init__(
        self,
        baseObject: str,
        scope: SearchScopes,
        derefAliases: DerefAliases,
        sizeLimit: int,
        timeLimit: int,
        typesOnly: bool,
        filter_: LDAPFilter,
        attributes: List[str],
    ):
        self.baseObject = baseObject
        self.scope = scope
        self.derefAliases = derefAliases
        self.sizeLimit = sizeLimit
        self.timeLimit = timeLimit
        self.typesOnly = typesOnly
        self.filter = filter_
        self.attributes = attributes

    def to_wire(self) -> bytes:
        return self.wrap([
            LDAPDN(self.baseObject),
            LDAPSearchScope(self.scope),
            LDAPDerefAlias(self.derefAliases),
            BERInteger(self.sizeLimit),
            BERInteger(self.timeLimit),
            BERBoolean(self.typesOnly),
            self.filter,
            LDAPAttributeSelection(self.attributes),
        ])

    def __repr__(self):
        base = self.baseObject
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + (
                "(baseObject=%s, scope=%s, derefAliases=%s, "
                + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, "
                "filter=%s, attributes=%s)"
            ) % (
                repr(base),
                self.scope,
                self.derefAliases,
                self.sizeLimit,
                self.timeLimit,
                self.typesOnly,
                repr(self.filter),
                self.attributes,
            )

        else:
            return self.__class__.__name__ + (
                "(baseObject=%s, scope=%s, derefAliases=%s, "
                + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, "
                "filter=%s, attributes=%s, tag=%d)"
            ) % (
                repr(base),
                self.scope,
                self.derefAliases,
                self.sizeLimit,
                self.timeLimit,
                self.typesOnly,
                repr(self.filter),
                self.attributes,
                self.tag,
            )


# SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
#      objectName      LDAPDN,
#      attributes      PartialAttributeList }
class LDAPSearchResultEntry(LDAPProtocolResponse, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x04

    objectName: str
    attributes: List[LDAPPartialAttribute]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPSearchResultEntry":
        vals = cls.unwrap(content)
        check(len(vals) == 2)
        objectName = decode(vals[0], LDAPDN).value
        attributes = decode(vals[1], LDAPPartialAttributeList).value
        return cls(objectName=objectName, attributes=attributes)

    def __init__(self, objectName: str, attributes: List[LDAPPartialAttribute]):
        self.objectName = objectName
        self.attributes = attributes

    def to_wire(self):
        return self.wrap([
            LDAPDN(self.objectName), LDAPPartialAttributeList(self.attributes)])

    def __repr__(self):
        name = self.objectName
        attributes = [(key, [v for v in value]) for (key, value) in self.attributes]
        return "{}(objectName={}, attributes={}{})".format(
            self.__class__.__name__,
            repr(name),
            repr(attributes),
            f", tag={self.tag}" if self.tag != self.__class__.tag else "",
        )


# SearchResultReference ::= [APPLICATION 19] SEQUENCE
#             SIZE (1..MAX) OF uri URI
class LDAPSearchResultReference(LDAPProtocolResponse, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x19
    value: List[str]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPSearchResultReference":
        vals = cls.unwrap(content)
        uris = [decode(val, LDAPURI).value for val in vals]
        return cls(uris=uris)

    def __init__(self, uris: List[str]):
        check(len(uris) >= 1)
        self.value = uris

    def to_wire(self) -> bytes:
        return self.wrap([LDAPURI(uri) for uri in self.value])


# SearchResultDone ::= [APPLICATION 5] LDAPResult
class LDAPSearchResultDone(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x05


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


class ModifyOperations(enum.IntEnum):
    add = 0
    delete = 1
    replace = 2
    # ...


class LDAPModify_operation(BEREnumerated):
    value: ModifyOperations

    @classmethod
    def enum_cls(cls) -> Type[enum.IntEnum]:
        return ModifyOperations


class LDAPModify_change(BERSequence):
    operation: ModifyOperations
    modification: LDAPPartialAttribute

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPModify_change":
        vals = cls.unwrap(content)
        check(len(vals) == 2)
        operation = decode(vals[0], LDAPModify_operation).value
        modification = decode(vals[1], LDAPPartialAttribute)
        return cls(operation=operation, modification=modification)

    def __init__(self, operation: ModifyOperations, modification: LDAPPartialAttribute):
        self.operation = operation
        self.modification = modification

    def to_wire(self) -> bytes:
        return self.wrap([LDAPModify_operation(self.operation), self.modification])


class LDAPModify_changes(BERSequence):
    value: List[LDAPModify_change]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPModify_changes":
        changes = [decode(val, LDAPModify_change) for val in cls.unwrap(content)]
        return cls(changes)

    def __init__(self, value: List[LDAPModify_change]):
        self.value = value

    def to_wire(self) -> bytes:
        return self.wrap(self.value)


# ModifyRequest ::= [APPLICATION 6] SEQUENCE {
#      object          LDAPDN,
#      changes         SEQUENCE OF change SEQUENCE {
#           operation       ENUMERATED {
#  add     (0),
#  delete  (1),
#  replace (2),
#  ...  },
#           modification    PartialAttribute } }
class LDAPModifyRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x06
    object: str
    changes: List[LDAPModify_change]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPModifyRequest":
        vals = cls.unwrap(content)
        check(len(vals) == 2)
        object_ = decode(vals[0], LDAPDN).value
        changes = decode(vals[1], LDAPModify_changes).value
        return cls(object_=object_, changes=changes)

    def __init__(self, object_: str, changes: List[LDAPModify_change]):
        self.object = object_
        self.changes = changes

    def to_wire(self) -> bytes:
        return self.wrap([LDAPDN(self.object), LDAPModify_changes(self.changes)])

    def __repr__(self):
        name = self.object
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(object={}, modification={})".format(
                repr(name),
                repr(self.changes),
            )
        else:
            return self.__class__.__name__ + "(object=%s, modification=%s, tag=%d)" % (
                repr(name),
                repr(self.changes),
                self.tag,
            )


# ModifyResponse ::= [APPLICATION 7] LDAPResult
class LDAPModifyResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x07


# AddRequest ::= [APPLICATION 8] SEQUENCE {
#      entry           LDAPDN,
#      attributes      AttributeList }
class LDAPAddRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x08
    entry: str
    attributes: List[LDAPAttribute]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPAddRequest":
        vals = cls.unwrap(content)
        check(len(vals) == 2)
        entry = decode(vals[0], LDAPDN).value
        attributes = decode(vals[1], LDAPAttributeList).value
        return cls(entry=entry, attributes=attributes)

    def __init__(self, entry: str, attributes: List[LDAPAttribute]):
        self.entry = entry
        self.attributes = attributes

    def to_wire(self) -> bytes:
        return self.wrap([LDAPDN(self.entry), LDAPAttributeList(self.attributes)])

    def __repr__(self):
        entry = self.entry
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(entry={}, attributes={})".format(
                repr(entry),
                repr(self.attributes),
            )
        else:
            return self.__class__.__name__ + "(entry=%s, attributes=%s, tag=%d)" % (
                repr(entry),
                repr(self.attributes),
                self.tag,
            )


# AddResponse ::= [APPLICATION 9] LDAPResult
class LDAPAddResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x09


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


FILTERS: Mapping[int, Type[LDAPFilter]] = {
    LDAPFilter_not.tag: LDAPFilter_not,
    LDAPFilter_equalityMatch.tag: LDAPFilter_equalityMatch,
    LDAPFilter_substrings.tag: LDAPFilter_substrings,
    LDAPFilter_greaterOrEqual.tag: LDAPFilter_greaterOrEqual,
    LDAPFilter_lessOrEqual.tag: LDAPFilter_lessOrEqual,
    LDAPFilter_present.tag: LDAPFilter_present,
    LDAPFilter_approxMatch.tag: LDAPFilter_approxMatch,
    LDAPFilter_extensibleMatch.tag: LDAPFilter_extensibleMatch,
}

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
