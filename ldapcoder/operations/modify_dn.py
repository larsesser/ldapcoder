"""LDAP protocol message conversion; no application logic here."""

from typing import List, Optional

from ldapcoder.berutils import BERBase, BERBoolean, BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, LDAPProtocolRequest, LDAPRelativeDN, check, decode,
)
from ldapcoder.registry import PROTOCOL_OPERATIONS
from ldapcoder.result import LDAPResult


class LDAPModifyDNResponse_newSuperior(LDAPDN):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00


# ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
#      entry           LDAPDN,
#      newrdn          RelativeLDAPDN,
#      deleteoldrdn    BOOLEAN,
#      newSuperior     [0] LDAPDN OPTIONAL }
@PROTOCOL_OPERATIONS.add
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

    def __repr__(self) -> str:
        attributes = [f"entry={self.entry}", f"newrdn={self.newrdn}",
                      f"deleteoldrdn={self.deleteoldrdn}"]
        if self.newSuperior is not None:
            attributes.append(f"newSuperior={self.newSuperior}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# ModifyDNResponse ::= [APPLICATION 13] LDAPResult
@PROTOCOL_OPERATIONS.add
class LDAPModifyDNResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0D
