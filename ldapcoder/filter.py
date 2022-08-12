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
