"""Implement the basic LDAP attribute types.

An objects attribute type bundles all syntactical information: The way it is decoded and
encoded (syntax), compared to other objects (matching rules) and how it is used.
"""

import abc
import enum
from typing import Any, Generic, List, TypeVar, Union

from ldapcoder.registry import ATTRIBUTE_TYPES
from ldapcoder.schema.matching_rules import (
    SYNTAX, BitStringMatchingRule, CaseIgnoreIA5MatchingRule,
    CaseIgnoreIA5SubstringsMatchingRule, CaseIgnoreListMatchingRule,
    CaseIgnoreListSubstringsMatchingRule, CaseIgnoreMatchingRule,
    CaseIgnoreOrderingMatchingRule, CaseIgnoreSubstringsMatchingRule,
    DistinguishedNameMatchingRule, EqualityMatchingRule, GeneralizedTimeMatchingRule,
    GeneralizedTimeOrderingMatchingRule, IntegerMatchingRule, NumericStringMatchingRule,
    NumericStringSubstringsMatchingRule, ObjectIdentifierFirstComponentMatchingRule,
    ObjectIdentifierMatchingRule, OctetStringMatchingRule, OrderingMatchingRule,
    SubstringMatchingRule, TelephoneNumberMatchingRule,
    TelephoneNumberSubstringsMatchingRule, UniqueMemberMatchingRule,
)
from ldapcoder.schema.syntaxes import (
    AttributeTypeDescriptionSyntax, BitStringSyntax, CountryStringSyntax,
    DeliveryMethodSyntax, DirectoryStringSyntax, DitContentRuleDescriptionSyntax,
    DitStructureRuleDescriptionSyntax, DnSyntax, EnhancedGuideSyntax,
    FacsimileTelephoneNumberSyntax, GeneralizedTimeSyntax, GuideSyntax, IA5StringSyntax,
    IntegerSyntax, MatchingRuleDescriptionSyntax, MatchingRuleUseDescriptionSyntax,
    NameAndOptionalUidSyntax, NameFormDescriptionSyntax, NumericStringSyntax,
    ObjectClassDescriptionSyntax, OctetStringSyntax, OidSyntax, PostalAddressSyntax,
    PrintableStringSyntax, SyntaxDescriptionSyntax, TelephoneNumberSyntax,
    TeletextTerminalIdentifierSyntax, TelexNumberSyntax,
)


class AttributeTypeUsages(enum.Enum):
    USER_APPLICATIONS = "userApplications"
    DIRECTORY_OPERATION = "directoryOperation"
    DISTRIBUTED_OPERATION = "distributedOperation"
    DSA_OPERATION = "dSAOperation"


ORDERING = TypeVar("ORDERING", bound=Union[None, OrderingMatchingRule[Any]])
EQUALITY = TypeVar("EQUALITY", bound=Union[None, EqualityMatchingRule[Any]])
SUBSTRING = TypeVar("SUBSTRING", bound=Union[None, SubstringMatchingRule[Any]])


# AttributeTypeDescription = LPAREN WSP
#          numericoid                    ; object identifier
#          [ SP "NAME" SP qdescrs ]      ; short names (descriptors)
#          [ SP "DESC" SP qdstring ]     ; description
#          [ SP "OBSOLETE" ]             ; not active
#          [ SP "SUP" SP oid ]           ; supertype
#          [ SP "EQUALITY" SP oid ]      ; equality matching rule
#          [ SP "ORDERING" SP oid ]      ; ordering matching rule
#          [ SP "SUBSTR" SP oid ]        ; substrings matching rule
#          [ SP "SYNTAX" SP noidlen ]    ; value syntax
#          [ SP "SINGLE-VALUE" ]         ; single-value
#          [ SP "COLLECTIVE" ]           ; collective
#          [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
#          [ SP "USAGE" SP usage ]       ; usage
#          extensions WSP RPAREN         ; extensions
#
#      usage = "userApplications"     /  ; user
#              "directoryOperation"   /  ; directory operational
#              "distributedOperation" /  ; DSA-shared operational
#              "dSAOperation"            ; DSA-specific operational
#
#    where:
#      <numericoid> is object identifier assigned to this attribute type;
#      NAME <qdescrs> are short names (descriptors) identifying this
#          attribute type;
#      DESC <qdstring> is a short descriptive string;
#      OBSOLETE indicates this attribute type is not active;
#      SUP oid specifies the direct supertype of this type;
#      EQUALITY, ORDERING, and SUBSTR provide the oid of the equality,
#          ordering, and substrings matching rules, respectively;
#      SYNTAX identifies value syntax by object identifier and may suggest
#          a minimum upper bound;
#      SINGLE-VALUE indicates attributes of this type are restricted to a
#          single value;
#      COLLECTIVE indicates this attribute type is collective
#          [X.501][RFC3671];
#      NO-USER-MODIFICATION indicates this attribute type is not user
#          modifiable;
#      USAGE indicates the application of this attribute type; and
#      <extensions> describe extensions.
class AttributeType(Generic[EQUALITY, ORDERING, SUBSTRING, SYNTAX], metaclass=abc.ABCMeta):
    numericoid: str = ""
    names: List[str] = []
    description: str = ""
    is_obsolete: bool = False
    equality: EQUALITY
    ordering: ORDERING
    substring: SUBSTRING
    syntax: SYNTAX
    is_single_valued: bool = False
    is_collective: bool = False
    is_user_modifiable: bool = True
    usage: AttributeTypeUsages


# ( 2.5.4.1 NAME 'aliasedObjectName'
#   EQUALITY distinguishedNameMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
#   SINGLE-VALUE )
# Section 2.6.2 of [RFC4512]
@ATTRIBUTE_TYPES.add
class AliasedObjectNameType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.4.1"
    names = ["aliasedObjectName"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()
    is_single_valued = True


# ( 2.5.4.0 NAME 'objectClass'
#   EQUALITY objectIdentifierMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
# Section 3.3 of [RFC4512]
@ATTRIBUTE_TYPES.add
class ObjectClassType(AttributeType[ObjectIdentifierMatchingRule, None, None, OidSyntax]):
    numericoid = "2.5.4.0"
    names = ["objectClass"]
    equality = ObjectIdentifierMatchingRule()
    ordering = None
    substring = None
    syntax = OidSyntax()


# ( 2.5.18.3 NAME 'creatorsName'
#   EQUALITY distinguishedNameMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
#   SINGLE-VALUE NO-USER-MODIFICATION
#   USAGE directoryOperation )
# Section 3.4.1 of [RFC4512]
@ATTRIBUTE_TYPES.add
class CreatorsNameType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.18.3"
    names = ["creatorsName"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()
    is_single_valued = True
    is_user_modifiable = False
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.18.1 NAME 'createTimestamp'
#   EQUALITY generalizedTimeMatch
#   ORDERING generalizedTimeOrderingMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
#   SINGLE-VALUE NO-USER-MODIFICATION
#   USAGE directoryOperation )
# Section 3.4.2 of [RFC4512]
@ATTRIBUTE_TYPES.add
class CreateTimestampType(AttributeType[GeneralizedTimeMatchingRule, GeneralizedTimeOrderingMatchingRule, None, GeneralizedTimeSyntax]):
    numericoid = "2.5.18.1"
    names = ["createTimestamp"]
    equality = GeneralizedTimeMatchingRule()
    ordering = GeneralizedTimeOrderingMatchingRule()
    substring = None
    syntax = GeneralizedTimeSyntax()
    is_single_valued = True
    is_user_modifiable = False
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.18.4 NAME 'modifiersName'
#   EQUALITY distinguishedNameMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
#   SINGLE-VALUE NO-USER-MODIFICATION
#   USAGE directoryOperation )
# Section 3.4.3 of [RFC4512]
@ATTRIBUTE_TYPES.add
class ModifiersNameType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.18.4"
    names = ["modifiersName"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()
    is_single_valued = True
    is_user_modifiable = False
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.18.2 NAME 'modifyTimestamp'
#   EQUALITY generalizedTimeMatch
#   ORDERING generalizedTimeOrderingMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
#   SINGLE-VALUE NO-USER-MODIFICATION
#   USAGE directoryOperation )
# Section 3.4.4 of [RFC4512]
@ATTRIBUTE_TYPES.add
class ModifyTimestampType(AttributeType[GeneralizedTimeMatchingRule, GeneralizedTimeOrderingMatchingRule, None, GeneralizedTimeSyntax]):
    numericoid = "2.5.18.2"
    names = ["modifyTimestamp"]
    equality = GeneralizedTimeMatchingRule()
    ordering = GeneralizedTimeOrderingMatchingRule()
    substring = None
    syntax = GeneralizedTimeSyntax()
    is_single_valued = True
    is_user_modifiable = False
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.9 NAME 'structuralObjectClass'
#   EQUALITY objectIdentifierMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
#   SINGLE-VALUE NO-USER-MODIFICATION
#   USAGE directoryOperation )
# Section 3.4.5 of [RFC4512]
@ATTRIBUTE_TYPES.add
class StructuralObjectClassType(AttributeType[ObjectIdentifierMatchingRule, None, None, OidSyntax]):
    numericoid = "2.5.21.9"
    names = ["structuralObjectClass"]
    equality = ObjectIdentifierMatchingRule()
    ordering = None
    substring = None
    syntax = OidSyntax()
    is_single_valued = True
    is_user_modifiable = False
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.10 NAME 'governingStructureRule'
#   EQUALITY integerMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
#   SINGLE-VALUE NO-USER-MODIFICATION
#   USAGE directoryOperation )
# Section 3.4.6 of [RFC4512]
@ATTRIBUTE_TYPES.add
class GoverningStructureRuleType(AttributeType[IntegerMatchingRule, None, None, IntegerSyntax]):
    numericoid = "2.5.21.10"
    names = ["governingStructureRule"]
    equality = IntegerMatchingRule()
    ordering = None
    substring = None
    syntax = IntegerSyntax()
    is_single_valued = True
    is_user_modifiable = False
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.18.10 NAME 'subschemaSubentry'
#   EQUALITY distinguishedNameMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
#   SINGLE-VALUE NO-USER-MODIFICATION
#   USAGE directoryOperation )
# Section 4.2 of [RFC4512]
@ATTRIBUTE_TYPES.add
class SubschemaSubentryType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.18.10"
    names = ["subschemaSubentry"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()
    is_single_valued = True
    is_user_modifiable = False
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.6 NAME 'objectClasses'
#   EQUALITY objectIdentifierFirstComponentMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.37
#   USAGE directoryOperation )
# Section 4.2.1 of [RFC4512]
@ATTRIBUTE_TYPES.add
class ObjectClassesType(AttributeType[ObjectIdentifierFirstComponentMatchingRule, None, None, ObjectClassDescriptionSyntax]):
    numericoid = "2.5.21.6"
    names = ["objectClasses"]
    equality = ObjectIdentifierFirstComponentMatchingRule()
    ordering = None
    substring = None
    syntax = ObjectClassDescriptionSyntax()
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.5 NAME 'attributeTypes'
#   EQUALITY objectIdentifierFirstComponentMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.3
#   USAGE directoryOperation )
# Section 4.2.2 of [RFC4512]
@ATTRIBUTE_TYPES.add
class AttributeTypesType(AttributeType[ObjectIdentifierFirstComponentMatchingRule, None, None, AttributeTypeDescriptionSyntax]):
    numericoid = "2.5.21.5"
    names = ["attributeTypes"]
    equality = ObjectIdentifierFirstComponentMatchingRule()
    ordering = None
    substring = None
    syntax = AttributeTypeDescriptionSyntax()
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.4 NAME 'matchingRules'
#   EQUALITY objectIdentifierFirstComponentMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.30
#   USAGE directoryOperation )
# Section 4.2.3 of [RFC4512]
@ATTRIBUTE_TYPES.add
class MatchingRulesType(AttributeType[ObjectIdentifierFirstComponentMatchingRule, None, None, MatchingRuleDescriptionSyntax]):
    numericoid = "2.5.21.4"
    names = ["matchingRules"]
    equality = ObjectIdentifierFirstComponentMatchingRule()
    ordering = None
    substring = None
    syntax = MatchingRuleDescriptionSyntax()
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.8 NAME 'matchingRuleUse'
#   EQUALITY objectIdentifierFirstComponentMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.31
#   USAGE directoryOperation )
# Section 4.2.4 of [RFC4512]
@ATTRIBUTE_TYPES.add
class MatchingRuleUseType(AttributeType[ObjectIdentifierFirstComponentMatchingRule, None, None, MatchingRuleUseDescriptionSyntax]):
    numericoid = "2.5.21.8"
    names = ["matchingRuleUse"]
    equality = ObjectIdentifierFirstComponentMatchingRule()
    ordering = None
    substring = None
    syntax = MatchingRuleUseDescriptionSyntax()
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes'
#   EQUALITY objectIdentifierFirstComponentMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.54
#   USAGE directoryOperation )
# Section 4.2.5 of [RFC4512]
@ATTRIBUTE_TYPES.add
class LdapSyntaxesType(AttributeType[ObjectIdentifierFirstComponentMatchingRule, None, None, SyntaxDescriptionSyntax]):
    numericoid = "1.3.6.1.4.1.1466.101.120.16"
    names = ["ldapSyntaxes"]
    equality = ObjectIdentifierFirstComponentMatchingRule()
    ordering = None
    substring = None
    syntax = SyntaxDescriptionSyntax()
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.2 NAME 'dITContentRules'
#   EQUALITY objectIdentifierFirstComponentMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.16
#   USAGE directoryOperation )
# Section 4.2.6 of [RFC4512]
@ATTRIBUTE_TYPES.add
class DitContentRulesType(AttributeType[ObjectIdentifierFirstComponentMatchingRule, None, None, DitContentRuleDescriptionSyntax]):
    numericoid = "2.5.21.2"
    names = ["dITContentRules"]
    equality = ObjectIdentifierFirstComponentMatchingRule()
    ordering = None
    substring = None
    syntax = DitContentRuleDescriptionSyntax()
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.1 NAME 'dITStructureRules'
#   EQUALITY integerFirstComponentMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.17
#   USAGE directoryOperation )
# Section 4.2.7 of [RFC4512]
@ATTRIBUTE_TYPES.add
class DitStructureRulesType(AttributeType[ObjectIdentifierFirstComponentMatchingRule, None, None, DitStructureRuleDescriptionSyntax]):
    numericoid = "2.5.21.1"
    names = ["dITStructureRules"]
    equality = ObjectIdentifierFirstComponentMatchingRule()
    ordering = None
    substring = None
    syntax = DitStructureRuleDescriptionSyntax()
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 2.5.21.7 NAME 'nameForms'
#   EQUALITY objectIdentifierFirstComponentMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.35
#   USAGE directoryOperation )
# Section 4.2.8 of [RFC4512]
@ATTRIBUTE_TYPES.add
class NameFormsType(AttributeType[ObjectIdentifierFirstComponentMatchingRule, None, None, NameFormDescriptionSyntax]):
    numericoid = "2.5.21.7"
    names = ["nameForms"]
    equality = ObjectIdentifierFirstComponentMatchingRule()
    ordering = None
    substring = None
    syntax = NameFormDescriptionSyntax()
    usage = AttributeTypeUsages.DIRECTORY_OPERATION


# ( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
#   USAGE dSAOperation )
# Section 5.1.1. of [RFC4512]
@ATTRIBUTE_TYPES.add
class AltServerType(AttributeType[None, None, None, IA5StringSyntax]):
    numericoid = "1.3.6.1.4.1.1466.101.120.6"
    names = ["altServer"]
    equality = None
    ordering = None
    substring = None
    syntax = IA5StringSyntax()
    usage = AttributeTypeUsages.DSA_OPERATION


# ( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
#   USAGE dSAOperation )
# Section 5.1.2. of [RFC4512]
@ATTRIBUTE_TYPES.add
class NamingcontextsType(AttributeType[None, None, None, DnSyntax]):
    numericoid = "1.3.6.1.4.1.1466.101.120.5"
    names = ["namingContexts"]
    equality = None
    ordering = None
    substring = None
    syntax = DnSyntax()
    usage = AttributeTypeUsages.DSA_OPERATION


# ( 1.3.6.1.4.1.1466.101.120.13 NAME 'supportedControl'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
#   USAGE dSAOperation )
# Section 5.1.3. of [RFC4512]
@ATTRIBUTE_TYPES.add
class SupportedControlType(AttributeType[None, None, None, OidSyntax]):
    numericoid = "1.3.6.1.4.1.1466.101.120.13"
    names = ["supportedControl"]
    equality = None
    ordering = None
    substring = None
    syntax = OidSyntax()
    usage = AttributeTypeUsages.DSA_OPERATION


# ( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
#   USAGE dSAOperation )
# Section 5.1.4. of [RFC4512]
@ATTRIBUTE_TYPES.add
class SupportedExtensionType(AttributeType[None, None, None, OidSyntax]):
    numericoid = "1.3.6.1.4.1.1466.101.120.7"
    names = ["supportedExtension"]
    equality = None
    ordering = None
    substring = None
    syntax = OidSyntax()
    usage = AttributeTypeUsages.DSA_OPERATION


# ( 1.3.6.1.4.1.4203.1.3.5 NAME 'supportedFeatures'
#   EQUALITY objectIdentifierMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
#   USAGE dSAOperation )
# Section 5.1.5. of [RFC4512]
@ATTRIBUTE_TYPES.add
class SupportedFeaturesType(AttributeType[ObjectIdentifierMatchingRule, None, None, OidSyntax]):
    numericoid = "1.3.6.1.4.1.4203.1.3.5"
    names = ["supportedFeatures"]
    equality = ObjectIdentifierMatchingRule()
    ordering = None
    substring = None
    syntax = OidSyntax()
    usage = AttributeTypeUsages.DSA_OPERATION


# ( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
#   USAGE dSAOperation )
# Section 5.1.6. of [RFC4512]
@ATTRIBUTE_TYPES.add
class SupportedLdapVersionType(AttributeType[None, None, None, IntegerSyntax]):
    numericoid = "1.3.6.1.4.1.1466.101.120.15"
    names = ["supportedLDAPVersion"]
    equality = None
    ordering = None
    substring = None
    syntax = IntegerSyntax()
    usage = AttributeTypeUsages.DSA_OPERATION


# ( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
#   USAGE dSAOperation )
# Section 5.1.6. of [RFC4512]
@ATTRIBUTE_TYPES.add
class SupportedSaslMechanismsType(AttributeType[None, None, None, DirectoryStringSyntax]):
    numericoid = "1.3.6.1.4.1.1466.101.120.14"
    names = ["supportedSASLMechanisms"]
    equality = None
    ordering = None
    substring = None
    syntax = DirectoryStringSyntax()
    usage = AttributeTypeUsages.DSA_OPERATION


# ( 2.5.4.15 NAME 'businessCategory'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.1. of [RFC4519]
@ATTRIBUTE_TYPES.add
class BusinessCategoryType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.15"
    names = ["businessCategory"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.6 NAME 'c'
#   SUP name
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.11
#   SINGLE-VALUE )
# Section 2.2. of [RFC4519]
@ATTRIBUTE_TYPES.add
class CType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, CountryStringSyntax]):
    numericoid = "2.5.4.6"
    names = ["c"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = CountryStringSyntax()
    is_single_valued = True


# ( 2.5.4.3 NAME 'cn'
#   SUP name )
# Section 2.3. of [RFC4519]
@ATTRIBUTE_TYPES.add
class CnType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.3"
    names = ["cn"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 0.9.2342.19200300.100.1.25 NAME 'dc'
#   EQUALITY caseIgnoreIA5Match
#   SUBSTR caseIgnoreIA5SubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
#   SINGLE-VALUE )
# Section 2.4. of [RFC4519]
@ATTRIBUTE_TYPES.add
class DcType(AttributeType[CaseIgnoreIA5MatchingRule, None, CaseIgnoreIA5SubstringsMatchingRule, IA5StringSyntax]):
    numericoid = "0.9.2342.19200300.100.1.25"
    names = ["dc"]
    equality = CaseIgnoreIA5MatchingRule()
    ordering = None
    substring = CaseIgnoreIA5SubstringsMatchingRule()
    syntax = IA5StringSyntax()
    is_single_valued = True


# ( 2.5.4.13 NAME 'description'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.5. of [RFC4519]
@ATTRIBUTE_TYPES.add
class DescriptionType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.13"
    names = ["description"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.27 NAME 'destinationIndicator'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
# Section 2.6. of [RFC4519]
@ATTRIBUTE_TYPES.add
class DestinationIndicatorType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, PrintableStringSyntax]):
    numericoid = "2.5.4.27"
    names = ["destinationIndicator"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = PrintableStringSyntax()


# ( 2.5.4.49 NAME 'distinguishedName'
#   EQUALITY distinguishedNameMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
# Section 2.7. of [RFC4519]
@ATTRIBUTE_TYPES.add
class DistinguishedNameType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.4.49"
    names = ["distinguishedName"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()


# ( 2.5.4.46 NAME 'dnQualifier'
#   EQUALITY caseIgnoreMatch
#   ORDERING caseIgnoreOrderingMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
# Section 2.8. of [RFC4519]
@ATTRIBUTE_TYPES.add
class DnQualifierType(AttributeType[CaseIgnoreMatchingRule, CaseIgnoreOrderingMatchingRule, CaseIgnoreSubstringsMatchingRule, PrintableStringSyntax]):
    numericoid = "2.5.4.46"
    names = ["dnQualifier"]
    equality = CaseIgnoreMatchingRule()
    ordering = CaseIgnoreOrderingMatchingRule()
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = PrintableStringSyntax()


# ( 2.5.4.47 NAME 'enhancedSearchGuide'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )
# Section 2.9. of [RFC4519]
@ATTRIBUTE_TYPES.add
class EnhancedSearchGuideType(AttributeType[None, None, None, EnhancedGuideSyntax]):
    numericoid = "2.5.4.47"
    names = ["enhancedSearchGuide"]
    equality = None
    ordering = None
    substring = None
    syntax = EnhancedGuideSyntax()


# ( 2.5.4.23 NAME 'facsimileTelephoneNumber'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.22 )
# Section 2.10. of [RFC4519]
@ATTRIBUTE_TYPES.add
class FacsimileTelephoneNumberType(AttributeType[None, None, None, FacsimileTelephoneNumberSyntax]):
    numericoid = "2.5.4.23"
    names = ["facsimileTelephoneNumber"]
    equality = None
    ordering = None
    substring = None
    syntax = FacsimileTelephoneNumberSyntax()


# ( 2.5.4.44 NAME 'generationQualifier'
#   SUP name )
# Section 2.11. of [RFC4519]
@ATTRIBUTE_TYPES.add
class GenerationQualifierType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.44"
    names = ["generationQualifier"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.42 NAME 'givenName'
#   SUP name )
# Section 2.12. of [RFC4519]
@ATTRIBUTE_TYPES.add
class GivenNameType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.42"
    names = ["givenName"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.51 NAME 'houseIdentifier'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.13. of [RFC4519]
@ATTRIBUTE_TYPES.add
class HouseIdentifierType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.51"
    names = ["houseIdentifier"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.43 NAME 'initials'
#   SUP name )
# Section 2.14. of [RFC4519]
@ATTRIBUTE_TYPES.add
class InitialsType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.43"
    names = ["initials"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.25 NAME 'internationalISDNNumber'
#          EQUALITY numericStringMatch
#          SUBSTR numericStringSubstringsMatch
#          SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
# Section 2.15 of [RFC4519]
@ATTRIBUTE_TYPES.add
class InternationalIsdnNumberType(AttributeType[NumericStringMatchingRule, None, NumericStringSubstringsMatchingRule, NumericStringSyntax]):
    numericoid = "2.5.4.25"
    names = ["internationalISDNNumber"]
    equality = NumericStringMatchingRule()
    ordering = None
    substring = NumericStringSubstringsMatchingRule()
    syntax = NumericStringSyntax()


# ( 2.5.4.7 NAME 'l'
#   SUP name )
# Section 2.16. of [RFC4519]
@ATTRIBUTE_TYPES.add
class LType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.7"
    names = ["l"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.31 NAME 'member'
#   SUP distinguishedName )
# Section 2.17. of [RFC4519]
@ATTRIBUTE_TYPES.add
class MemberType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.4.31"
    names = ["member"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()


# ( 2.5.4.41 NAME 'name'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.18. of [RFC4519]
@ATTRIBUTE_TYPES.add
class NameType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.41"
    names = ["name"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.10 NAME 'o'
#   SUP name )
# Section 2.19. of [RFC4519]
@ATTRIBUTE_TYPES.add
class OType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.10"
    names = ["o"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.11 NAME 'ou'
#   SUP name )
# Section 2.20. of [RFC4519]
@ATTRIBUTE_TYPES.add
class OuType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.11"
    names = ["ou"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.32 NAME 'owner'
#   SUP distinguishedName )
# Section 2.21. of [RFC4519]
@ATTRIBUTE_TYPES.add
class OwnerType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.4.32"
    names = ["owner"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()


# ( 2.5.4.19 NAME 'physicalDeliveryOfficeName'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.22. of [RFC4519]
@ATTRIBUTE_TYPES.add
class PhysicalDeliveryOfficeNameType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.19"
    names = ["physicalDeliveryOfficeName"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.16 NAME 'postalAddress'
#   EQUALITY caseIgnoreListMatch
#   SUBSTR caseIgnoreListSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
# Section 2.23. of [RFC4519]
@ATTRIBUTE_TYPES.add
class PostalAddressType(AttributeType[CaseIgnoreListMatchingRule, None, CaseIgnoreListSubstringsMatchingRule, PostalAddressSyntax]):
    numericoid = "2.5.4.16"
    names = ["postalAddress"]
    equality = CaseIgnoreListMatchingRule()
    ordering = None
    substring = CaseIgnoreListSubstringsMatchingRule()
    syntax = PostalAddressSyntax()


# ( 2.5.4.17 NAME 'postalCode'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.24. of [RFC4519]
@ATTRIBUTE_TYPES.add
class PostalCodeType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.17"
    names = ["postalCode"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.18 NAME 'postOfficeBox'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.25. of [RFC4519]
@ATTRIBUTE_TYPES.add
class PostOfficeBox(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.18"
    names = ["postOfficeBox"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.28 NAME 'preferredDeliveryMethod'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.14
#   SINGLE-VALUE )
# Section 2.26. of [RFC4519]
@ATTRIBUTE_TYPES.add
class PreferredDeliveryMethod(AttributeType[None, None, None, DeliveryMethodSyntax]):
    numericoid = "2.5.4.28"
    names = ["preferredDeliveryMethod"]
    equality = None
    ordering = None
    substring = None
    syntax = DeliveryMethodSyntax()
    is_single_valued = True


# ( 2.5.4.26 NAME 'registeredAddress'
#   SUP postalAddress
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
# Section 2.27. of [RFC4519]
@ATTRIBUTE_TYPES.add
class RegisteredAddressType(AttributeType[CaseIgnoreListMatchingRule, None, CaseIgnoreListSubstringsMatchingRule, PostalAddressSyntax]):
    numericoid = "2.5.4.26"
    names = ["registeredAddress"]
    equality = CaseIgnoreListMatchingRule()
    ordering = None
    substring = CaseIgnoreListSubstringsMatchingRule()
    syntax = PostalAddressSyntax()


# ( 2.5.4.33 NAME 'roleOccupant'
#   SUP distinguishedName )
# Section 2.28. of [RFC4519]
@ATTRIBUTE_TYPES.add
class RoleOccupantType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.4.33"
    names = ["roleOccupant"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()


# ( 2.5.4.14 NAME 'searchGuide'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.25 )
# Section 2.29. of [RFC4519]
@ATTRIBUTE_TYPES.add
class SearchGuideType(AttributeType[None, None, None, GuideSyntax]):
    numericoid = "2.5.4.14"
    names = ["searchGuide"]
    equality = None
    ordering = None
    substring = None
    syntax = GuideSyntax()


# ( 2.5.4.34 NAME 'seeAlso'
#   SUP distinguishedName )
# Section 2.30. of [RFC4519]
@ATTRIBUTE_TYPES.add
class SeeAlsoType(AttributeType[DistinguishedNameMatchingRule, None, None, DnSyntax]):
    numericoid = "2.5.4.34"
    names = ["seeAlso"]
    equality = DistinguishedNameMatchingRule()
    ordering = None
    substring = None
    syntax = DnSyntax()


# ( 2.5.4.5 NAME 'serialNumber'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
# Section 2.31. of [RFC4519]
@ATTRIBUTE_TYPES.add
class SerialNumberType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, PrintableStringSyntax]):
    numericoid = "2.5.4.5"
    names = ["serialNumber"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = PrintableStringSyntax()


# ( 2.5.4.4 NAME 'sn'
#   SUP name )
# Section 2.32. of [RFC4519]
@ATTRIBUTE_TYPES.add
class SnType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.4"
    names = ["sn"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.8 NAME 'st'
#   SUP name )
# Section 2.33. of [RFC4519]
@ATTRIBUTE_TYPES.add
class StType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.8"
    names = ["st"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.9 NAME 'street'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.34. of [RFC4519]
@ATTRIBUTE_TYPES.add
class StreetType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.9"
    names = ["street"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.20 NAME 'telephoneNumber'
#   EQUALITY telephoneNumberMatch
#   SUBSTR telephoneNumberSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
# Section 2.35. of [RFC4519]
@ATTRIBUTE_TYPES.add
class TelephoneNumberType(AttributeType[TelephoneNumberMatchingRule, None, TelephoneNumberSubstringsMatchingRule, TelephoneNumberSyntax]):
    numericoid = "2.5.4.20"
    names = ["telephoneNumber"]
    equality = TelephoneNumberMatchingRule()
    ordering = None
    substring = TelephoneNumberSubstringsMatchingRule()
    syntax = TelephoneNumberSyntax()


# ( 2.5.4.22 NAME 'teletexTerminalIdentifier'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.51 )
# Section 2.36. of [RFC4519]
@ATTRIBUTE_TYPES.add
class TeletexTerminalIdentifierType(AttributeType[None, None, None, TeletextTerminalIdentifierSyntax]):
    numericoid = "2.5.4.22"
    names = ["teletexTerminalIdentifier"]
    equality = None
    ordering = None
    substring = None
    syntax = TeletextTerminalIdentifierSyntax()


# ( 2.5.4.21 NAME 'telexNumber'
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.52 )
# Section 2.37. of [RFC4519]
@ATTRIBUTE_TYPES.add
class TeletexNumberType(AttributeType[None, None, None, TelexNumberSyntax]):
    numericoid = "2.5.4.21"
    names = ["telexNumber"]
    equality = None
    ordering = None
    substring = None
    syntax = TelexNumberSyntax()


# ( 2.5.4.12 NAME 'title'
#   SUP name )
# Section 2.38. of [RFC4519]
@ATTRIBUTE_TYPES.add
class TitelType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "2.5.4.12"
    names = ["title"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 0.9.2342.19200300.100.1.1 NAME 'uid'
#   EQUALITY caseIgnoreMatch
#   SUBSTR caseIgnoreSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
# Section 2.39. of [RFC4519]
@ATTRIBUTE_TYPES.add
class UidType(AttributeType[CaseIgnoreMatchingRule, None, CaseIgnoreSubstringsMatchingRule, DirectoryStringSyntax]):
    numericoid = "0.9.2342.19200300.100.1.1"
    names = ["uid"]
    equality = CaseIgnoreMatchingRule()
    ordering = None
    substring = CaseIgnoreSubstringsMatchingRule()
    syntax = DirectoryStringSyntax()


# ( 2.5.4.50 NAME 'uniqueMember'
#   EQUALITY uniqueMemberMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )
# Section 2.40. of [RFC4519]
@ATTRIBUTE_TYPES.add
class UniqueMemberType(AttributeType[UniqueMemberMatchingRule, None, None, NameAndOptionalUidSyntax]):
    numericoid = "2.5.4.50"
    names = ["uniqueMember"]
    equality = UniqueMemberMatchingRule()
    ordering = None
    substring = None
    syntax = NameAndOptionalUidSyntax()


# ( 2.5.4.35 NAME 'userPassword'
#   EQUALITY octetStringMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
# Section 2.41. of [RFC4519]
@ATTRIBUTE_TYPES.add
class UserPasswordType(AttributeType[OctetStringMatchingRule, None, None, OctetStringSyntax]):
    numericoid = "2.5.4.35"
    names = ["userPassword"]
    equality = OctetStringMatchingRule()
    ordering = None
    substring = None
    syntax = OctetStringSyntax()


# ( 2.5.4.24 NAME 'x121Address'
#   EQUALITY numericStringMatch
#   SUBSTR numericStringSubstringsMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
# Section 2.42. of [RFC4519]
@ATTRIBUTE_TYPES.add
class X121AddressType(AttributeType[NumericStringMatchingRule, None, NumericStringSubstringsMatchingRule, NumericStringSyntax]):
    numericoid = "2.5.4.24"
    names = ["x121Address"]
    equality = NumericStringMatchingRule()
    ordering = None
    substring = NumericStringSubstringsMatchingRule()
    syntax = NumericStringSyntax()


# ( 2.5.4.45 NAME 'x500UniqueIdentifier'
#   EQUALITY bitStringMatch
#   SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )
# Section 2.43. of [RFC4519]
@ATTRIBUTE_TYPES.add
class X500UniqueIdentifierType(AttributeType[BitStringMatchingRule, None, None, BitStringSyntax]):
    numericoid = "2.5.4.45"
    names = ["x500UniqueIdentifier"]
    equality = BitStringMatchingRule()
    ordering = None
    substring = None
    syntax = BitStringSyntax()
