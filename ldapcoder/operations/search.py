"""LDAP protocol message conversion; no application logic here."""

import enum
from typing import List, Type

from ldapcoder.berutils import (
    BERBoolean, BEREnumerated, BERInteger, BERSequence, TagClasses, UnknownBERTag,
)
from ldapcoder.filter import FILTERS, LDAPFilter
from ldapcoder.ldaputils import (
    LDAPDN, LDAPURI, LDAPAttributeSelection, LDAPPartialAttribute,
    LDAPPartialAttributeList, LDAPProtocolRequest, LDAPProtocolResponse, check, decode,
)
from ldapcoder.result import LDAPResult


@enum.unique
class SearchScopes(enum.IntEnum):
    baseObject = 0
    singleLevel = 1
    wholeSubtree = 2
    # ...


class LDAPSearchScope(BEREnumerated):
    value: SearchScopes

    @classmethod
    def enum_cls(cls) -> Type[enum.IntEnum]:
        return SearchScopes


@enum.unique
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
    _tag = 0x13
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
