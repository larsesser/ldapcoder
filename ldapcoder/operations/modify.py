"""LDAP protocol message conversion; no application logic here."""

import enum
from typing import List, Type

from ldapcoder.berutils import BEREnumerated, BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, LDAPPartialAttribute, LDAPProtocolRequest, check, decode,
)
from ldapcoder.result import LDAPResult


@enum.unique
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

    def __repr__(self) -> str:
        attributes = [f"operation={self.operation!r}", f"modification={self.modification!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


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

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value!r})"


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

    def __repr__(self) -> str:
        attributes = [f"object={self.object}", f"changes={self.changes!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# ModifyResponse ::= [APPLICATION 7] LDAPResult
class LDAPModifyResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x07
