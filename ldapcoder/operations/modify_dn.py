"""LDAP protocol message conversion; no application logic here."""

from typing import List, Optional

from ldapcoder.berutils import BERBase, BERBoolean, BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, DistinguishedName, LDAPProtocolRequest, LDAPRelativeDN,
    RelativeDistinguishedName, decode,
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
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPModifyDNRequest(LDAPProtocolRequest, BERSequence):
    """Rename the RDN of an entry, and/or move a subtree of entries to a new location.

    Note that the entry may have children (subordinates)!

    If the new DN of the entry is already present, the operation will fail.

    Servers MUST ensure that entries conform to user and system schema rules or other
    data model constraints.

    The server SHALL NOT dereference any aliases in locating the objects named in entry
    or newSuperior.
    """
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0C

    entry: DistinguishedName
    newrdn: RelativeDistinguishedName
    deleteoldrdn: bool
    newSuperior: Optional[DistinguishedName]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPModifyDNRequest":
        vals = cls.unwrap(content)
        if len(vals) < 3:
            cls.handle_missing_vals(vals)
        if len(vals) > 4:
            cls.handle_additional_vals(vals[4:])

        entry = decode(vals[0], LDAPDN).dn
        newrdn = decode(vals[1], LDAPRelativeDN).rdn
        deleteoldrdn = decode(vals[2], BERBoolean).boolean
        newSuperior = None
        if len(vals) >= 4:
            newSuperior = decode(vals[3], LDAPModifyDNResponse_newSuperior).dn
        return cls(entry=entry, newrdn=newrdn, deleteoldrdn=deleteoldrdn, newSuperior=newSuperior)

    def __init__(self, entry: DistinguishedName, newrdn: RelativeDistinguishedName,
                 deleteoldrdn: bool, newSuperior: DistinguishedName = None):
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
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPModifyDNResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x0D
