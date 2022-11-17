"""Implement the basic LDAP matching rules.

There are three different kinds of matching rules:
- EqualityMatchingRules determine if two objects are equal.
- OrderingMatchingRules establish an ordering relation between two objects.
- SubstringMatchingRules determine if a given object is part of another object.

MatchingRules may be used in AttributeTypes.
"""

import abc
from typing import TYPE_CHECKING, Generic, List, Optional, TypeVar

from ldapcoder.schema.syntaxes import (
    BitStringSyntax, BooleanSyntax, DirectoryStringSyntax, DnSyntax,
    GeneralizedTimeSyntax, IA5StringSyntax, IntegerSyntax, LdapSyntax,
    NameAndOptionalUidSyntax, NumericStringSyntax, OctetStringSyntax, OidSyntax,
    PostalAddressSyntax, SubstringAssertionSyntax, TelephoneNumberSyntax,
)

if TYPE_CHECKING:
    from ldapcoder.ldaputils import SingleValuedAttribute


SYNTAX = TypeVar("SYNTAX", bound=LdapSyntax)


# MatchingRuleDescription = LPAREN WSP
#          numericoid                 ; object identifier
#          [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
#          [ SP "DESC" SP qdstring ]  ; description
#          [ SP "OBSOLETE" ]          ; not active
#          SP "SYNTAX" SP numericoid  ; assertion syntax
#          extensions WSP RPAREN      ; extensions
#
#    where:
#      <numericoid> is object identifier assigned to this matching rule;
#      NAME <qdescrs> are short names (descriptors) identifying this
#          matching rule;
#      DESC <qdstring> is a short descriptive string;
#      OBSOLETE indicates this matching rule is not active;
#      SYNTAX identifies the assertion syntax (the syntax of the assertion
#          value) by object identifier; and
#      <extensions> describe extensions.
class MatchingRule(Generic[SYNTAX], metaclass=abc.ABCMeta):
    """Base class of all matching rules used in LDAP.

    numericoid: The numericoid of this matching rule.
    names: Zero or more short names (caseinsensitive) identifying this matching rule.
        Take care that they may be ambiguous between matching rules, and not unique with
        regard to AttributeDescriptions or ObjectClasses.
    description: A short string describing this object class.
    is_obsolete: Indicates if this object class is active or not.
    syntax: The syntax of the assertion value.
    """
    numericoid: str = ""
    names: List[str] = []
    description: str = ""
    is_obsolete: bool = False
    syntax: SYNTAX

    def __eq__(self, other):
        if not isinstance(other, MatchingRule):
            return False
        return self.numericoid == other.numericoid


class EqualityMatchingRule(MatchingRule[SYNTAX], metaclass=abc.ABCMeta):
    @classmethod
    def equals_rule(cls, attribute: "SingleValuedAttribute", assertion: bytes) -> Optional[bool]:
        raise NotImplementedError


class OrderingMatchingRule(MatchingRule[SYNTAX], metaclass=abc.ABCMeta):
    @classmethod
    def lesser_rule(cls, attribute: "SingleValuedAttribute", assertion: bytes) -> Optional[bool]:
        raise NotImplementedError


class SubstringMatchingRule(MatchingRule[SYNTAX], metaclass=abc.ABCMeta):
    @classmethod
    def contains_rule(cls, attribute: "SingleValuedAttribute", assertion: bytes) -> Optional[bool]:
        raise NotImplementedError


# ( 2.5.13.16 NAME 'bitStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )
# Section 4.2.1. of [RFC4517]
class BitStringMatchingRule(EqualityMatchingRule[BitStringSyntax]):
    numericoid = "2.5.13.16"
    names = ["bitStringMatch"]
    syntax = BitStringSyntax()

    @classmethod
    def equals_rule(cls, attribute: "SingleValuedAttribute", assertion: bytes) -> Optional[bool]:
        # TODO cover case if the corresponding ASN.1 type of the attribute syntax has a
        #  named bit list
        return attribute.description.type.syntax.decode_value(attribute.value) == cls.syntax.decode_value(assertion)


# ( 2.5.13.13 NAME 'booleanMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )
# Section 4.2.2. of [RFC4517]
class BooleanMatchingRule(EqualityMatchingRule[BooleanSyntax]):
    numericoid = "2.5.13.13"
    names = ["booleanMatch"]
    syntax = BooleanSyntax()


# ( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
# Section 4.2.3. of [RFC4517]
class CaseExactIA5MatchingRule(EqualityMatchingRule[IA5StringSyntax]):
    numericoid = "1.3.6.1.4.1.1466.109.114.1"
    names = ["caseExactIA5Match"]
    syntax = IA5StringSyntax()


# ( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 4.2.4. of [RFC4517]
class CaseExactMatch(EqualityMatchingRule[DirectoryStringSyntax]):
    numericoid = "2.5.13.5"
    names = ["caseExactMatch"]
    syntax = DirectoryStringSyntax()


# ( 2.5.13.6 NAME 'caseExactOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 4.2.5. of [RFC4517]
class CaseExactOrderingMatchingRule(OrderingMatchingRule[DirectoryStringSyntax]):
    numericoid = "2.5.13.6"
    names = ["caseExactOrderingMatch"]
    syntax = DirectoryStringSyntax()


# ( 2.5.13.7 NAME 'caseExactSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
# Section 4.2.6. of [RFC4517]
class CaseExactSubstringMatchingRule(SubstringMatchingRule[SubstringAssertionSyntax]):
    numericoid = "2.5.13.7"
    names = ["caseExactSubstringsMatch"]
    syntax = SubstringAssertionSyntax()


# ( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
# Section 4.2.7. of [RFC4517]
class CaseIgnoreIA5MatchingRule(EqualityMatchingRule[IA5StringSyntax]):
    numericoid = "1.3.6.1.4.1.1466.109.114.2"
    names = ["caseIgnoreIA5Match"]
    syntax = IA5StringSyntax()


# ( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
# Section 4.2.8. of [RFC4517]
class CaseIgnoreIA5SubstringsMatchingRule(SubstringMatchingRule[SubstringAssertionSyntax]):
    numericoid = "1.3.6.1.4.1.1466.109.114.3"
    names = ["caseIgnoreIA5SubstringsMatch"]
    syntax = SubstringAssertionSyntax()


# ( 2.5.13.11 NAME 'caseIgnoreListMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
# Section 4.2.9. of [RFC4517]
class CaseIgnoreListMatchingRule(EqualityMatchingRule[PostalAddressSyntax]):
    numericoid = "2.5.13.11"
    names = ["caseIgnoreListMatch"]
    syntax = PostalAddressSyntax()


# ( 2.5.13.12 NAME 'caseIgnoreListSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
# Section 4.2.10. of [RFC4517]
class CaseIgnoreListSubstringsMatchingRule(SubstringMatchingRule[SubstringAssertionSyntax]):
    numericoid = "2.5.13.12"
    names = ["caseIgnoreListSubstringsMatch"]
    syntax = SubstringAssertionSyntax()


# ( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 4.2.11. of [RFC4517]
class CaseIgnoreMatchingRule(EqualityMatchingRule[DirectoryStringSyntax]):
    numericoid = "2.5.13.2"
    names = ["caseIgnoreMatch"]
    syntax = DirectoryStringSyntax()


# ( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 4.2.12. of [RFC4517]
class CaseIgnoreOrderingMatchingRule(OrderingMatchingRule[DirectoryStringSyntax]):
    numericoid = "2.5.13.3"
    names = ["caseIgnoreOrderingMatch"]
    syntax = DirectoryStringSyntax()


# ( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
# Section 4.2.13. of [RFC4517]
class CaseIgnoreSubstringsMatchingRule(SubstringMatchingRule[SubstringAssertionSyntax]):
    numericoid = "2.5.13.4"
    names = ["caseIgnoreSubstringsMatch"]
    syntax = SubstringAssertionSyntax()


# ( 2.5.13.31 NAME 'directoryStringFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 4.2.14. of [RFC4517]
class DirectoryStringFirstComponentMatchingRule(EqualityMatchingRule[DirectoryStringSyntax]):
    numericoid = "2.5.13.31"
    names = ["directoryStringFirstComponentMatch"]
    syntax = DirectoryStringSyntax()


# ( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
# Section 4.2.15. of [RFC4517]
class DistinguishedNameMatchingRule(EqualityMatchingRule[DnSyntax]):
    numericoid = "2.5.13.1"
    names = ["distinguishedNameMatch"]
    syntax = DnSyntax()


# ( 2.5.13.27 NAME 'generalizedTimeMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )
# Section 4.2.16. of [RFC4517]
class GeneralizedTimeMatchingRule(EqualityMatchingRule[GeneralizedTimeSyntax]):
    numericoid = "2.5.13.27"
    names = ["generalizedTimeMatch"]
    syntax = GeneralizedTimeSyntax()


# ( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )
# Section 4.2.17. of [RFC4517]
class GeneralizedTimeOrderingMatchingRule(OrderingMatchingRule[GeneralizedTimeSyntax]):
    numericoid = "2.5.13.28"
    names = ["generalizedTimeOrderingMatch"]
    syntax = GeneralizedTimeSyntax()


# ( 2.5.13.29 NAME 'integerFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
# Section 4.2.18. of [RFC4517]
class IntegerFirstComponentMatchingRule(EqualityMatchingRule[IntegerSyntax]):
    numericoid = "2.5.13.29"
    names = ["integerFirstComponentMatch"]
    syntax = IntegerSyntax()


# ( 2.5.13.14 NAME 'integerMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
# Section 4.2.19. of [RFC4517]
class IntegerMatchingRule(EqualityMatchingRule[IntegerSyntax]):
    numericoid = "2.5.13.14"
    names = ["integerMatch"]
    syntax = IntegerSyntax()


# ( 2.5.13.15 NAME 'integerOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
# Section 4.2.20. of [RFC4517]
class IntegerOrderingMatchingRule(OrderingMatchingRule[IntegerSyntax]):
    numericoid = "2.5.13.15"
    names = ["integerOrderingMatch"]
    syntax = IntegerSyntax()


# ( 2.5.13.33 NAME 'keywordMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 4.2.21. of [RFC4517]
# TODO class KeywordMatchingRule


# ( 2.5.13.8 NAME 'numericStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
# Section 4.2.22. of [RFC4517]
class NumericStringMatchingRule(EqualityMatchingRule[NumericStringSyntax]):
    numericoid = "2.5.13.8"
    names = ["numericStringMatch"]
    syntax = NumericStringSyntax()


# ( 2.5.13.9 NAME 'numericStringOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
# Section 4.2.23. of [RFC4517]
class NumericStringOrderingMatchingRule(OrderingMatchingRule[NumericStringSyntax]):
    numericoid = "2.5.13.9"
    names = ["numericStringOrderingMatch"]
    syntax = NumericStringSyntax()


# ( 2.5.13.10 NAME 'numericStringSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
# Section 4.2.24. of [RFC4517]
class NumericStringSubstringsMatchingRule(SubstringMatchingRule[SubstringAssertionSyntax]):
    numericoid = "2.5.13.10"
    names = ["numericStringSubstringsMatch"]
    syntax = SubstringAssertionSyntax()


# ( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
# Section 4.2.25. of [RFC4517]
class ObjectIdentifierFirstComponentMatchingRule(EqualityMatchingRule[OidSyntax]):
    numericoid = "2.5.13.30"
    names = ["objectIdentifierFirstComponentMatch"]
    syntax = OidSyntax()


# ( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
# Section 4.2.26. of [RFC4517]
class ObjectIdentifierMatchingRule(EqualityMatchingRule[OidSyntax]):
    numericoid = "2.5.13.0"
    names = ["objectIdentifierMatch"]
    syntax = OidSyntax()


# ( 2.5.13.17 NAME 'octetStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
# Section 4.2.27. of [RFC4517]
class OctetStringMatchingRule(EqualityMatchingRule[OctetStringSyntax]):
    numericoid = "2.5.13.17"
    names = ["octetStringMatch"]
    syntax = OctetStringSyntax()


# ( 2.5.13.18 NAME 'octetStringOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
# Section 4.2.28. of [RFC4517]
class OctetStringOrderingMatchingRule(OrderingMatchingRule[OctetStringSyntax]):
    numericoid = "2.5.13.18"
    names = ["octetStringOrderingMatch"]
    syntax = OctetStringSyntax()


# ( 2.5.13.20 NAME 'telephoneNumberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
# Section 4.2.29. of [RFC4517]
class TelephoneNumberMatchingRule(EqualityMatchingRule[TelephoneNumberSyntax]):
    numericoid = "2.5.13.20"
    names = ["telephoneNumberMatch"]
    syntax = TelephoneNumberSyntax()


# ( 2.5.13.21 NAME 'telephoneNumberSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
# Section 4.2.30. of [RFC4517]
class TelephoneNumberSubstringsMatchingRule(SubstringMatchingRule[SubstringAssertionSyntax]):
    numericoid = "2.5.13.21"
    names = ["telephoneNumberSubstringsMatch"]
    syntax = SubstringAssertionSyntax()


# ( 2.5.13.23 NAME 'uniqueMemberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )
# Section 4.2.31. of [RFC4517]
class UniqueMemberMatchingRule(EqualityMatchingRule[NameAndOptionalUidSyntax]):
    numericoid = "2.5.13.23"
    names = ["uniqueMemberMatch"]
    syntax = NameAndOptionalUidSyntax()


# ( 2.5.13.32 NAME 'wordMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 4.2.32. of [RFC4517]
# TODO class WordMatchingRule
