"""LDAP protocol message conversion; no application logic here."""

import enum
from typing import List, Type

from ldapcoder.berutils import BEREnumerated, BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, DistinguishedName, LDAPPartialAttribute, LDAPProtocolRequest, decode,
)
from ldapcoder.registry import PROTOCOL_OPERATIONS
from ldapcoder.result import LDAPResult


@enum.unique
class ModifyOperations(enum.IntEnum):
    """The ModifyOperations as defined in Sec. 4.6. of [RFC4511]."""
    add = 0
    delete = 1
    replace = 2
    # ...


class LDAPModify_operation(BEREnumerated):
    member: ModifyOperations

    @classmethod
    def enum_cls(cls) -> Type[enum.IntEnum]:
        return ModifyOperations


class LDAPModify_change(BERSequence):
    operation: ModifyOperations
    modification: LDAPPartialAttribute

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPModify_change":
        vals = cls.unwrap(content)
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])
        operation = decode(vals[0], LDAPModify_operation).member
        modification = decode(vals[1], LDAPPartialAttribute)
        return cls(operation=operation, modification=modification)

    def __init__(self, operation: ModifyOperations, modification: LDAPPartialAttribute):
        self.operation = operation
        self.modification = modification

    def to_wire(self) -> bytes:
        return self.wrap([LDAPModify_operation(self.operation), self.modification])

    def __repr__(self) -> str:
        attributes = [f"operation={self.operation!r}", f"modification={self.modification!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


class LDAPModify_changes(BERSequence):
    changes: List[LDAPModify_change]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPModify_changes":
        changes = [decode(val, LDAPModify_change) for val in cls.unwrap(content)]
        return cls(changes)

    def __init__(self, value: List[LDAPModify_change]):
        self.changes = value

    def to_wire(self) -> bytes:
        return self.wrap(self.changes)

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.changes!r})"


# ModifyRequest ::= [APPLICATION 6] SEQUENCE {
#      object          LDAPDN,
#      changes         SEQUENCE OF change SEQUENCE {
#           operation       ENUMERATED {
#  add     (0),
#  delete  (1),
#  replace (2),
#  ...  },
#           modification    PartialAttribute } }
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPModifyRequest(LDAPProtocolRequest, BERSequence):
    """Request to modify the object with the given changes.

    Each change specifies via the operation enum if the modification should be added,
    deleted or replaced for the object. Either all changes should be applied by the
    server, or none (think of the ModifyRequest being in an atomized context).

    The server MUST ensure that the entry conform to user and system schema rules or
    other data model constraints after applying all changes.

    The server SHALL NOT perform any alias dereferencing in determining the object to be
    modified.
    """
    _tag_class = TagClasses.APPLICATION
    _tag = 0x06
    object: DistinguishedName
    changes: List[LDAPModify_change]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPModifyRequest":
        vals = cls.unwrap(content)
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])
        object_ = decode(vals[0], LDAPDN).dn
        changes = decode(vals[1], LDAPModify_changes).changes
        return cls(object_=object_, changes=changes)

    def __init__(self, object_: DistinguishedName, changes: List[LDAPModify_change]):
        self.object = object_
        self.changes = changes

    def to_wire(self) -> bytes:
        return self.wrap([LDAPDN(self.object), LDAPModify_changes(self.changes)])

    def __repr__(self) -> str:
        attributes = [f"object={self.object}", f"changes={self.changes!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# ModifyResponse ::= [APPLICATION 7] LDAPResult
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPModifyResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x07
