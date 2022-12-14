"""LDAP protocol message conversion; no application logic here."""

import enum
from typing import List, Type

from ldapcoder.berutils import (
    BERBoolean, BEREnumerated, BERInteger, BERSequence, TagClasses,
)
from ldapcoder.exceptions import UnknownTagError
from ldapcoder.filter import LDAPFilter
from ldapcoder.ldaputils import (
    LDAPDN, LDAPURI, DistinguishedName, LDAPAttributeSelection, LDAPPartialAttribute,
    LDAPPartialAttributeList, LDAPProtocolRequest, LDAPProtocolResponse, decode,
)
from ldapcoder.registry import FILTERS, PROTOCOL_OPERATIONS
from ldapcoder.result import LDAPResult


@enum.unique
class SearchScopes(enum.IntEnum):
    """The SearchScopes as defined in Sec. 4.5.1.2. of [RFC4511]."""
    baseObject = 0
    singleLevel = 1
    wholeSubtree = 2
    # ...


class LDAPSearchScope(BEREnumerated):
    member: SearchScopes

    @classmethod
    def enum_cls(cls) -> Type[enum.IntEnum]:
        return SearchScopes


@enum.unique
class DerefAliases(enum.IntEnum):
    """The DerefAliases as defined in Sec. 4.5.1.3. of [RFC4511]."""
    neverDerefAliases = 0
    derefInSearching = 1
    derefFindingBaseObj = 2
    derefAlways = 3


class LDAPDerefAlias(BEREnumerated):
    member: DerefAliases

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
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPSearchRequest(LDAPProtocolRequest, BERSequence):
    """Query the server for entries matching the given search conditions."""
    _tag_class = TagClasses.APPLICATION
    _tag = 0x03

    baseObject: DistinguishedName
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
        if len(vals) < 8:
            cls.handle_missing_vals(vals)
        if len(vals) > 8:
            cls.handle_additional_vals(vals[8:])

        baseObject = decode(vals[0], LDAPDN).dn
        scope = decode(vals[1], LDAPSearchScope).member
        derefAlias = decode(vals[2], LDAPDerefAlias).member
        sizeLimit = decode(vals[3], BERInteger).integer
        timeLimit = decode(vals[4], BERInteger).integer
        typesOnly = decode(vals[5], BERBoolean).boolean
        filter_tag, filter_content = vals[6]
        if filter_tag not in FILTERS:
            raise UnknownTagError(filter_tag)
        filter_ = FILTERS[filter_tag].from_wire(filter_content)
        attributes = decode(vals[7], LDAPAttributeSelection).selectors

        return cls(
            baseObject=baseObject,
            scope=scope,
            derefAliases=derefAlias,
            sizeLimit=sizeLimit,
            timeLimit=timeLimit,
            typesOnly=typesOnly,
            filter_=filter_,
            attributes=attributes,
        )

    def __init__(
        self,
        baseObject: DistinguishedName,
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

    def __repr__(self) -> str:
        attributes = [
            f"baseObject={self.baseObject}", f"scope={self.scope!r}",
            f"derefAliases={self.derefAliases!r}", f"sizeLimit={self.sizeLimit}",
            f"timeLimit={self.timeLimit}", f"typesOnly={self.typesOnly}",
            f"filter={self.filter!r}", f"attributes={self.attributes}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
#      objectName      LDAPDN,
#      attributes      PartialAttributeList }
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPSearchResultEntry(LDAPProtocolResponse, BERSequence):
    """Return one entry matching the specified search conditions."""
    _tag_class = TagClasses.APPLICATION
    _tag = 0x04

    objectName: DistinguishedName
    attributes: List[LDAPPartialAttribute]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPSearchResultEntry":
        vals = cls.unwrap(content)
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])
        objectName = decode(vals[0], LDAPDN).dn
        attributes = decode(vals[1], LDAPPartialAttributeList).partial_attributes
        return cls(objectName=objectName, attributes=attributes)

    def __init__(self, objectName: DistinguishedName, attributes: List[LDAPPartialAttribute]):
        self.objectName = objectName
        self.attributes = attributes

    def to_wire(self) -> bytes:
        return self.wrap([
            LDAPDN(self.objectName), LDAPPartialAttributeList(self.attributes)])

    def __repr__(self) -> str:
        attributes = [f"objectName={self.objectName}", f"attributes={self.attributes!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# SearchResultReference ::= [APPLICATION 19] SEQUENCE
#             SIZE (1..MAX) OF uri URI
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPSearchResultReference(LDAPProtocolResponse, BERSequence):
    """References to other LDAPServers which hold one of the requested entries.

    This works in analogy to LDAPReferrals.
    """
    _tag_class = TagClasses.APPLICATION
    _tag = 0x13
    uris: List[str]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPSearchResultReference":
        vals = cls.unwrap(content)
        uris = [decode(val, LDAPURI).string for val in vals]
        return cls(uris=uris)

    def __init__(self, uris: List[str]):
        if len(uris) == 0:
            raise ValueError(f"{self.__class__.__name__} expects at least one uri.")
        self.uris = uris

    def to_wire(self) -> bytes:
        return self.wrap([LDAPURI(uri) for uri in self.uris])

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.uris})"


# SearchResultDone ::= [APPLICATION 5] LDAPResult
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPSearchResultDone(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x05
