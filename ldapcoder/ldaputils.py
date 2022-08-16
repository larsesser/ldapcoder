"""LDAP protocol message conversion; no application logic here."""

import abc
import string
from typing import TYPE_CHECKING, Dict, Generic, List, Optional, Tuple, Type, TypeVar

from ldapcoder.berutils import (
    BERBase, BERInteger, BEROctetString, BERSequence, BERSet, int2berlen,
)

if TYPE_CHECKING:
    from ldapcoder.result import ResultCodes

next_ldap_message_id = 1


def alloc_ldap_message_id() -> int:
    global next_ldap_message_id
    r = next_ldap_message_id
    next_ldap_message_id = next_ldap_message_id + 1
    return r


def escape(s: str) -> str:
    s = s.replace("\\", r"\5c")
    s = s.replace("*", r"\2a")
    s = s.replace("(", r"\28")
    s = s.replace(")", r"\29")
    s = s.replace("\0", r"\00")
    return s


def binary_escape(s: str) -> str:
    return "".join(f"\\{ord(c):02x}" for c in s)


def smart_escape(s: str, threshold: float = 0.30) -> str:
    binary_count = sum(c not in string.printable for c in s)
    if float(binary_count) / float(len(s)) > threshold:
        return binary_escape(s)
    return escape(s)


def check(statement: bool, msg: str = "") -> None:
    """Check that the given statement is true.

    If not, raise an error with the given message. Thought of this like assert statements,
    with the difference that this one does actually raise exceptions.
    """
    if not statement:
        raise ValueError(msg)


T = TypeVar("T")


def decode(input_: Tuple[int, bytes], class_: Type[T]) -> T:
    """Decode a (tag, content) tuple into an instance of the given BER class."""
    tag, content = input_
    assert issubclass(class_, BERBase)
    check(tag == class_.tag, msg=f"Given tag: {tag}, expected tag: {class_.tag}")
    # TODO can we show mypy that T is always a subclass of BERBase?
    return class_.from_wire(content)  # type: ignore[return-value]


KT = TypeVar("KT")
VT = TypeVar("VT")


class Registry(Generic[KT, VT]):
    """Store items and enable the end user of the library to add additional ones."""
    _items: Dict[KT, VT]

    def __init__(self, items: Dict[KT, VT]):
        self._items = items

    def __getitem__(self, item: KT) -> VT:
        return self._items[item]

    def __contains__(self, item: KT) -> bool:
        return item in self._items

    def __call__(self, item: VT) -> VT:
        """Enables the storage object to be used as decorator on the item definition."""
        # TODO nicer error message if item is not of expected type
        self.add(item)
        return item

    @abc.abstractmethod
    def add(self, item: VT) -> None:
        raise NotImplementedError


# LDAPString ::= OCTET STRING -- UTF-8 encoded,
#               -- [ISO10646] characters
class LDAPString(BEROctetString):
    value: str  # type: ignore[assignment]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPString":
        check(len(content) >= 0)
        utf8 = content.decode("utf-8")
        # TODO should this be escaped or not?
        # value = escape(utf8)
        return cls(utf8)

    def __init__(self, value: str):
        super().__init__(value)  # type: ignore[arg-type]

    def to_wire(self) -> bytes:
        encoded = self.value.encode("utf-8")
        return bytes((self.tag,)) + int2berlen(len(self.value)) + encoded


# LDAPDN ::= LDAPString  -- Constrained to <distinguishedName> [RFC4514]
class LDAPDN(LDAPString):
    pass


# RelativeLDAPDN ::= LDAPString
#      -- Constrained to <name-component> [RFC4514]
class LDAPRelativeDN(LDAPString):
    pass


# URI ::= LDAPString     -- limited to characters permitted in URIs
class LDAPURI(LDAPString):
    pass


# AttributeValue ::= OCTET STRING
class LDAPAttributeValue(BEROctetString):
    pass


# MessageID ::= INTEGER (0 ..  maxInt)
# maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
class LDAPMessageId(BERInteger):
    pass


class LDAPProtocolOp(BERBase, metaclass=abc.ABCMeta):
    pass


class LDAPProtocolRequest(LDAPProtocolOp, metaclass=abc.ABCMeta):
    needs_answer = 1


class LDAPProtocolResponse(LDAPProtocolOp, metaclass=abc.ABCMeta):
    pass


class LDAPException(Exception):
    resultCode: "ResultCodes"
    message: Optional[bytes]

    def __init__(self, resultCode: "ResultCodes", message: bytes = None):
        self.resultCode = resultCode
        self.message = message


# AttributeDescription ::= LDAPString
#           -- Constrained to <attributedescription>
#           -- [RFC4512]
class LDAPAttributeDescription(LDAPString):
    pass


# AssertionValue ::= OCTET STRING
class LDAPAssertionValue(BEROctetString):
    pass


# AttributeValueAssertion ::= SEQUENCE {
#      attributeDesc   AttributeDescription,
#      assertionValue  AssertionValue }
class LDAPAttributeValueAssertion(BERSequence):
    attributeDesc: str
    assertionValue: bytes

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPAttributeValueAssertion":
        vals = cls.unwrap(content)
        check(len(vals) == 2)
        attributeDesc = decode(vals[0], LDAPAttributeDescription).value
        assertionValue = decode(vals[1], LDAPAssertionValue).value
        return cls(attributeDesc=attributeDesc, assertionValue=assertionValue)

    def __init__(self, attributeDesc: str, assertionValue: bytes):
        self.attributeDesc = attributeDesc
        self.assertionValue = assertionValue

    def to_wire(self) -> bytes:
        return self.wrap([LDAPAttributeDescription(self.attributeDesc),
                          LDAPAssertionValue(self.assertionValue)])

    def __repr__(self) -> str:
        attributes = [f"attributeDesc={self.attributeDesc}",
                      f"assertionValue={self.assertionValue!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# AttributeSelection ::= SEQUENCE OF selector LDAPString
#   -- The LDAPString is constrained to
#   -- <attributeSelector> in Section 4.5.1.8
class LDAPAttributeSelection(BERSequence):
    value: List[str]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPAttributeSelection":
        value = [decode(val, LDAPString).value for val in cls.unwrap(content)]
        return cls(value)

    def __init__(self, value: List[str]):
        self.value = value

    def to_wire(self) -> bytes:
        return self.wrap([LDAPString(val) for val in self.value])

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value})"


class LDAPAttributeValueSet(BERSet):
    value: List[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPAttributeValueSet":
        value = [decode(val, LDAPAttributeValue).value for val in cls.unwrap(content)]
        return cls(value)

    def __init__(self, value: List[bytes]):
        self.value = value

    def to_wire(self) -> bytes:
        return self.wrap([LDAPAttributeValue(val) for val in self.value])

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value!r})"


# PartialAttribute ::= SEQUENCE {
#      type       AttributeDescription,
#      vals       SET OF value AttributeValue }
class LDAPPartialAttribute(BERSequence):
    type_: str
    values: List[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPPartialAttribute":
        vals = cls.unwrap(content)
        check(len(vals) == 2)
        type_ = decode(vals[0], LDAPAttributeDescription).value
        values = decode(vals[1], LDAPAttributeValueSet).value
        return cls(type_=type_, values=values)

    def __init__(self, type_: str, values: List[bytes]):
        self.type_ = type_
        self.values = values

    def to_wire(self) -> bytes:
        return self.wrap([
            LDAPAttributeDescription(self.type_), LDAPAttributeValueSet(self.values)])

    def __repr__(self) -> str:
        attributes = [f"type_={self.type_}", f"values={self.values!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# PartialAttributeList ::= SEQUENCE OF
#        partialAttribute PartialAttribute
class LDAPPartialAttributeList(BERSequence):
    value: List[LDAPPartialAttribute]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPPartialAttributeList":
        value = [decode(val, LDAPPartialAttribute) for val in cls.unwrap(content)]
        return cls(value)

    def __init__(self, value: List[LDAPPartialAttribute]):
        self.value = value

    def to_wire(self) -> bytes:
        return self.wrap(self.value)

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value!r}"


# Attribute ::= PartialAttribute(WITH COMPONENTS {
#      ...,
#      vals (SIZE(1..MAX))})
class LDAPAttribute(LDAPPartialAttribute):
    def __init__(self, type_: str, values: List[bytes]):
        check(len(values) >= 1)
        super().__init__(type_, values)


# AttributeList ::= SEQUENCE OF attribute Attribute
class LDAPAttributeList(BERSequence):
    value: List[LDAPAttribute]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPAttributeList":
        value = [decode(val, LDAPAttribute) for val in cls.unwrap(content)]
        return cls(value)

    def __init__(self, value: List[LDAPAttribute]):
        self.value = value

    def to_wire(self) -> bytes:
        return self.wrap(self.value)

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value!r}"


# LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
#            -- [RFC4512]
class LDAPOID(BEROctetString):
    pass
