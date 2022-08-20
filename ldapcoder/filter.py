"""LDAP protocol message conversion; no application logic here."""

import abc
import logging
from typing import Any, List, Optional

from ldapcoder.berutils import (
    BERBase, BERBoolean, BERSequence, BERSet, TagClasses, ber_unwrap, berlen,
)
from ldapcoder.exceptions import (
    DecodingError, DuplicateTagReceivedError, UnknownTagError,
)
from ldapcoder.ldaputils import (
    LDAPAssertionValue, LDAPAttributeDescription, LDAPAttributeValueAssertion,
    LDAPString, decode, escape,
)
from ldapcoder.registry import FILTERS, SUBSTRINGS

logger = logging.getLogger(__name__)


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


class LDAPFilterSet(LDAPFilter, BERSet, metaclass=abc.ABCMeta):
    filters: List[LDAPFilter]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPFilterSet":
        vals = cls.unwrap(content)
        filters = []
        for filter_tag, filter_content in vals:
            if filter_tag not in FILTERS:
                raise UnknownTagError(filter_tag)
            filters.append(FILTERS[filter_tag].from_wire(filter_content))
        # the from_wire method returns BERBase objects, but we know they are LDAPFilters
        return cls(filters)  # type: ignore[arg-type]

    def __init__(self, filters: List[LDAPFilter]):
        # TODO is this behaviour changed by a follow up RFC?
        # At least one filter element MUST be present in an 'and' or 'or' choice.
        # check(len(filters) >= 1)
        self.filters = filters

    def __eq__(self, rhs: Any) -> bool:
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

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.filters!r})"


@FILTERS.add
class LDAPFilter_and(LDAPFilterSet):
    _tag = 0x00

    @property
    def as_text(self) -> str:
        return "(&" + "".join([x.as_text for x in self.filters]) + ")"


@FILTERS.add
class LDAPFilter_or(LDAPFilterSet):
    _tag = 0x01

    @property
    def as_text(self) -> str:
        return "(|" + "".join([x.as_text for x in self.filters]) + ")"


@FILTERS.add
class LDAPFilter_not(LDAPFilter):
    _tag_is_constructed = True
    _tag = 0x02
    value: LDAPFilter

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPFilter_not":
        [val], bytes_used = ber_unwrap(content)
        if bytes_used != len(content):
            raise DecodingError(f"Trailing bytes detected: {content[bytes_used:]!r}")

        filter_tag, filter_content = val
        if filter_tag not in FILTERS:
            raise UnknownTagError(filter_tag)
        value = FILTERS[filter_tag].from_wire(filter_content)
        # the from_wire method returns BERBase objects, but we know they are LDAPFilters
        assert isinstance(value, LDAPFilter)
        return cls(value)

    def __init__(self, value: LDAPFilter):
        self.value = value

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value!r})"

    def to_wire(self) -> bytes:
        value_bytes = self.value.to_wire()
        return bytes((self.tag,)) + berlen(value_bytes) + value_bytes

    @property
    def as_text(self) -> str:
        return "(!" + self.value.as_text + ")"


@FILTERS.add
class LDAPFilter_equalityMatch(LDAPFilter, LDAPAttributeValueAssertion):
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
        return super().from_wire(content)  # type: ignore[return-value]

    @property
    def as_text(self) -> str:
        return escape(self.value.decode("utf-8"))


@SUBSTRINGS.add
class LDAPFilter_substrings_initial(LDAPFilter_substrings_string):
    _tag = 0x00


@SUBSTRINGS.add
class LDAPFilter_substrings_any(LDAPFilter_substrings_string):
    _tag = 0x01


@SUBSTRINGS.add
class LDAPFilter_substrings_final(LDAPFilter_substrings_string):
    _tag = 0x02


class LDAP_substrings(BERSequence):
    value: List[LDAPFilter_substrings_string]

    @classmethod
    def from_wire(cls, content: bytes) -> "BERBase":
        vals = cls.unwrap(content)
        substrings = []
        for substring_tag, substring_content in vals:
            if substring_tag not in SUBSTRINGS:
                raise UnknownTagError(substring_tag)
            substring = SUBSTRINGS[substring_tag].from_wire(substring_content)
            substrings.append(substring)
        return cls(value=substrings)

    def __init__(self, value: List[LDAPFilter_substrings_string]):
        if len(value) == 0:
            raise ValueError(f"{self.__class__.__name__} expects at least one element.")
        # There SHALL be at most one 'initial' and at most one 'final' in the
        # 'substrings' of a SubstringFilter.
        if sum(1 for s in value if isinstance(s, LDAPFilter_substrings_initial)) > 1:
            logger.warning("More than one initial substring detected.")
        if sum(1 for s in value if isinstance(s, LDAPFilter_substrings_final)) > 1:
            logger.warning("More than one final substring detected.")
        self.value = value

    def to_wire(self) -> bytes:
        return self.wrap(self.value)

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value!r})"


# SubstringFilter ::= SEQUENCE {
#      type           AttributeDescription,
#      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
#           initial [0] AssertionValue,  -- can occur at most once
#           any     [1] AssertionValue,
#           final   [2] AssertionValue } -- can occur at most once
#      }
@FILTERS.add
class LDAPFilter_substrings(LDAPFilter, BERSequence):
    _tag = 0x04
    type: str
    substrings: List[LDAPFilter_substrings_string]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPFilter_substrings":
        vals = cls.unwrap(content)
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])

        type_ = decode(vals[0], LDAPAttributeDescription).value
        substrings = decode(vals[1], LDAP_substrings).value
        return cls(type_=type_, substrings=substrings)

    def __init__(self, type_: str, substrings: List[LDAPFilter_substrings_string]):
        self.type = type_
        # do validation
        self.substrings = LDAP_substrings(substrings).value

    def to_wire(self) -> bytes:
        return self.wrap([LDAPAttributeDescription(self.type), LDAP_substrings(self.substrings)])

    def __repr__(self) -> str:
        attributes = [f"type={self.type}", f"substrings={self.substrings!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"

    @property
    def as_text(self) -> str:
        initial_string = ""
        any_string: List[str] = []
        final_string = ""

        for string in self.substrings:
            if isinstance(string, LDAPFilter_substrings_initial):
                initial_string = string.as_text
            elif isinstance(string, LDAPFilter_substrings_any):
                any_string.append(string.as_text)
            elif isinstance(string, LDAPFilter_substrings_final):
                final_string = string.as_text
            else:
                # TODO error more gracefully?
                raise NotImplementedError(f"Filter type not supported: {string!r}")

        return "(" + self.type + "=" + "*".join([initial_string, *any_string, final_string]) + ")"


@FILTERS.add
class LDAPFilter_greaterOrEqual(LDAPFilter, LDAPAttributeValueAssertion):
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


@FILTERS.add
class LDAPFilter_lessOrEqual(LDAPFilter, LDAPAttributeValueAssertion):
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


@FILTERS.add
class LDAPFilter_present(LDAPFilter, LDAPAttributeDescription):
    _tag = 0x07

    @property
    def as_text(self) -> str:
        return "(" + self.value + "=*)"


@FILTERS.add
class LDAPFilter_approxMatch(LDAPFilter, LDAPAttributeValueAssertion):
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
        if len(vals) == 0:
            cls.handle_missing_vals(vals)

        matchingRule = None
        type_ = None
        matchValue = None
        dnAttributes = None

        additional = []
        for unknown_tag, unknown_content in vals:
            if unknown_tag == LDAPMatchingRuleAssertion_matchingRule.tag:
                if matchingRule is not None:
                    raise DuplicateTagReceivedError("matchingRule")
                matchingRule = LDAPMatchingRuleAssertion_matchingRule.from_wire(unknown_content).value
            elif unknown_tag == LDAPMatchingRuleAssertion_type.tag:
                if type_ is not None:
                    raise DuplicateTagReceivedError("type")
                type_ = LDAPMatchingRuleAssertion_type.from_wire(unknown_content).value
            elif unknown_tag == LDAPMatchingRuleAssertion_matchValue.tag:
                if matchValue is not None:
                    raise DuplicateTagReceivedError("matchValue")
                matchValue = LDAPMatchingRuleAssertion_matchValue.from_wire(unknown_content).value
            elif unknown_tag == LDAPMatchingRuleAssertion_dnAttributes.tag:
                if dnAttributes is not None:
                    raise DuplicateTagReceivedError("dnAttributes")
                dnAttributes = LDAPMatchingRuleAssertion_dnAttributes.from_wire(unknown_content).value
            else:
                additional.append((unknown_tag, unknown_content))
        if additional:
            cls.handle_additional_vals(additional)

        if matchValue is None:
            raise DecodingError("matchValue is missing.")
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
        to_send.append(LDAPMatchingRuleAssertion_matchValue(self.matchValue))
        if self.dnAttributes is not None:
            to_send.append(LDAPMatchingRuleAssertion_dnAttributes(self.dnAttributes))
        return self.wrap(to_send)

    def __repr__(self) -> str:
        attributes = []
        if self.matchingRule is not None:
            attributes.append(f"matchingRule={self.matchingRule}")
        if self.type is not None:
            attributes.append(f"type={self.type}")
        attributes.append(f"matchValue={self.matchValue!r}")
        if self.dnAttributes is not None:
            attributes.append(f"dnAttributes={self.dnAttributes}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


@FILTERS.add
class LDAPFilter_extensibleMatch(LDAPFilter, LDAPMatchingRuleAssertion):
    _tag = 0x09

    def __init__(
            self,
            matchValue: bytes,
            matchingRule: str = None,
            type_: str = None,
            dnAttributes: bool = None,
    ):
        # If the matchingRule field is absent, the type field MUST be
        # present, and an equality match is performed for that type.
        if matchingRule is None and type_ is None:
            raise ValueError("Type must be present if matchingRule is absent.")
        super().__init__(matchingRule=matchingRule, type_=type_, matchValue=matchValue, dnAttributes=dnAttributes)

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
