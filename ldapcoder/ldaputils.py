"""LDAP protocol message conversion; no application logic here."""

import abc
import string
from typing import TYPE_CHECKING, List, Optional, Tuple, Type, TypeVar

from ldapcoder.berutils import (
    BERBase, BERInteger, BEROctetString, BERSequence, BERSet, int2berlen,
)

if TYPE_CHECKING:
    from ldapcoder.result import ResultCodes


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
#
# distinguishedName = [ relativeDistinguishedName *( COMMA relativeDistinguishedName ) ]
# relativeDistinguishedName = attributeTypeAndValue *( PLUS attributeTypeAndValue )
# attributeTypeAndValue = attributeType EQUALS attributeValue
# attributeType = descr / numericoid
# attributeValue = string / hexstring
#
# ; The following characters are to be escaped when they appear
# ; in the value to be encoded: ESC, one of <escaped>, leading
# ; SHARP or SPACE, trailing SPACE, and NULL.
# string =   [ ( leadchar / pair ) [ *( stringchar / pair )
#   ( trailchar / pair ) ] ]
#
# leadchar = LUTF1 / UTFMB
# LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A /
#   %x3D / %x3F-5B / %x5D-7F
#
# trailchar  = TUTF1 / UTFMB
# TUTF1 = %x01-1F / %x21 / %x23-2A / %x2D-3A /
#    %x3D / %x3F-5B / %x5D-7F
#
# stringchar = SUTF1 / UTFMB
# SUTF1 = %x01-21 / %x23-2A / %x2D-3A /
#   %x3D / %x3F-5B / %x5D-7F
#
# pair = ESC ( ESC / special / hexpair )
# special = escaped / SPACE / SHARP / EQUALS
# escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
# hexstring = SHARP 1*hexpair
# hexpair = HEX HEX
class LDAPDN(LDAPString):
    pass


# RelativeLDAPDN ::= LDAPString
#      -- Constrained to <name-component> [RFC4514]
class LDAPRelativeDN(LDAPString):
    pass


# URI ::= LDAPString     -- limited to characters permitted in URIs
class LDAPURI(LDAPString):
    pass


# LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
#            -- [RFC4512]
# numericoid = number 1*( DOT number )
class LDAPOID(BEROctetString):
    value: str  # type: ignore[assignment]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPOID":
        check(len(content) >= 0)
        return cls(content.decode("utf-8"))

    def __init__(self, value: str):
        # validate the given value to be a numericoid
        check(all(components.isnumeric() for components in value.split(".")))
        super().__init__(value)  # type: ignore[arg-type]

    def to_wire(self) -> bytes:
        encoded = self.value.encode("utf-8")
        return bytes((self.tag,)) + int2berlen(len(self.value)) + encoded


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
# attributedescription = attributetype options
# attributetype = oid
# options = *( SEMI option )
# option = 1*keychar
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
# attributeSelector = attributedescription / selectorspecial
# selectorspecial = noattrs / alluserattrs
# noattrs = %x31.2E.31 ; "1.1"
# alluserattrs = %x2A ; asterisk ("*")
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
        # No two of the attribute values may be equivalent as described by
        # Section 2.2 of [RFC4512]
        check(len(value) == len(set(value)))
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
