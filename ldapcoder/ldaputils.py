"""LDAP protocol message conversion; no application logic here."""

import abc
import binascii
import string
from string import hexdigits as HEXDIGITS
from typing import (
    TYPE_CHECKING, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Type,
    TypeVar, Union,
)

from ldapcoder.berutils import (
    BERBase, BERInteger, BEROctetString, BERSequence, BERSet, berlen,
)
from ldapcoder.exceptions import DecodingError, EncodingError

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


T = TypeVar("T")


def decode(input_: Tuple[int, bytes], class_: Type[T]) -> T:
    """Decode a (tag, content) tuple into an instance of the given BER class."""
    tag, content = input_
    assert issubclass(class_, BERBase)
    if tag != class_.tag:
        raise DecodingError(f"Expected tag {class_.tag}, got {tag} instead.")
    # TODO can we show mypy that T is always a subclass of BERBase?
    return class_.from_wire(content)  # type: ignore[return-value]


# LDAPString ::= OCTET STRING -- UTF-8 encoded,
#               -- [ISO10646] characters
class LDAPString(BEROctetString):
    value: str  # type: ignore[assignment]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPString":
        try:
            utf8 = content.decode("utf-8")
        except UnicodeDecodeError as e:
            raise DecodingError from e
        # TODO should this be escaped or not?
        # value = escape(utf8)
        return cls(utf8)

    def __init__(self, value: str):
        super().__init__(value)  # type: ignore[arg-type]

    def to_wire(self) -> bytes:
        try:
            encoded = self.value.encode("utf-8")
        except UnicodeEncodeError as e:
            raise EncodingError from e
        return bytes((self.tag,)) + berlen(encoded) + encoded


def escaped_split(string: str, delim: str, escape: str = '\\') -> List[str]:
    """Helper function for advanced string splitting.

    Split the string at every delimiter, except if it is escaped (and allow the escape
    char to be escaped itself).

    Take special care to remove the escape char only iff it escaped the delimiter.

    Based on http://stackoverflow.com/a/18092547
    """
    ret = []
    current = ''
    itr: Iterator[str] = iter(string)
    for char in itr:
        if char == escape:
            try:
                next_char = next(itr)
            except StopIteration:
                continue
            if next_char == delim:
                current += next_char
            else:
                current += escape + next_char
        elif char == delim:
            ret.append(current)
            current = ''
        else:
            current += char
    ret.append(current)
    return ret


class RelativeDistinguishedName:
    # The AttributeTypeAndValues (short: attributes) forming an RDN are an unordered
    # set, implying each attribute (descriptor/numericoid) is unique and order is
    # irrelevant, see Sec. 2.3.1 [RFC4512] and Sec. 2.2 [RFC4514]
    # Additionally, as part of an RDN, each attribute has one and only one value. This
    # is also true for multivalued attributes, see Sec. 2.2 [RFC4512]

    # key: descriptor/numericoid of the attribute
    # value: the unescaped (!) string representation of the attributes value
    # Attributes are stored in this form if they were passed as ...
    # - ... string, in string representation
    # - ... LDAPAttribute object where AttributeDescription is a descriptor
    attributes: Dict[str, str]
    # key: descriptor/numericoid of the attribute
    # value: the byte representation of the AttributeValue (including tag, length and content)
    # Attributes are stored in this form if they were passed as ...
    # - ... string, in hexstring representation
    # - ... LDAPAttribute object where AttributeDescription is a numericoid
    bytes_attributes: Dict[str, bytes]
    # special character which need to be escaped if they occur in the attribute's value
    _ESCAPE = "\\"
    _ESCAPED_LEADING = {"#", " "}
    _ESCAPED_EVERYWHERE = {'"', "+", ",", ";", "<", ">"}
    _ESCAPED_TRAILING = {" "}
    _ESCAPED_AS_HEX = {chr(0x00)}

    def __init__(self, raw: Union[str, "LDAPAttribute", Iterable["LDAPAttribute"]]) -> None:
        self.attributes = {}
        self.bytes_attributes = {}
        if isinstance(raw, str):
            for pair in escaped_split(raw, delim="+"):
                splitted = escaped_split(pair, delim="=")
                if len(splitted) != 2:
                    raise DecodingError(f"Malformed AttributeTypeAndValues in RDN: {pair}")
                attribute, value = splitted[0], splitted[1]
                # decide if the attribute is stored in bytes or in string representation
                if self.is_hexstring(value):
                    self.bytes_attributes[attribute] = self._unescape_hexstring(value)
                else:
                    self.attributes[attribute] = self._unescape_string(value)
            return

        if isinstance(raw, LDAPAttribute):
            raw = [raw]
        for attribute_ in raw:
            if len(attribute_.values) != 1:
                raise ValueError
            # decide if the attribute is stored in bytes or in string representation
            if is_numericoid(attribute_.type_):
                self.bytes_attributes[attribute_.type_] = attribute_.to_wire()
            else:
                self.attributes[attribute_.type_] = attribute_.values

    def __str__(self) -> str:
        return self.string

    @staticmethod
    def is_hexstring(value: str) -> bool:
        return value.startswith("#")

    @property
    def string(self) -> str:
        """The (escaped) string representation of the RDN."""
        # the order of those is irrelevant. However, we want to ensure its stable,
        # even if it's not required.
        attributes = sorted(self.attributes.items())
        bytes_attributes = sorted(self.bytes_attributes.items())
        string_attributes = [f"{attribute}={self._escape_string(value)}"
                             for attribute, value in attributes]
        hexstring_attributes = [f"{attribute}={self._escape_hexstring(value)}"
                                for attribute, value in bytes_attributes]
        return "+".join([*string_attributes, *hexstring_attributes])

    @staticmethod
    def _escape_hexstring(value: bytes) -> str:
        """Escape the value.

        See Sec. 2.4 [RFC4514].
        """
        prefix = "#"
        return prefix + binascii.hexlify(value).decode("utf-8")

    @classmethod
    def _escape_string(cls, value: str) -> str:
        """Escape the value, so it may be used in the RDNs string representation."""
        # escape the escape char first, so we do not accidentally escape this twice.
        value = value.replace(cls._ESCAPE, cls._ESCAPE + cls._ESCAPE)
        # replace chars which need to be escaped everywhere ...
        for char in cls._ESCAPED_EVERYWHERE:
            value = value.replace(char, cls._ESCAPE + char)
        # ... only at the beginning ...
        for char in cls._ESCAPED_LEADING:
            if value.startswith(char):
                value = cls._ESCAPE + value
        # ... and only at the end of the string.
        for char in cls._ESCAPED_TRAILING:
            if value.endswith(char):
                value = value[:-1] + cls._ESCAPE + char
        # Following Sec. 2.4 [RFC4514], some characters must be escaped as hex digits
        for char in cls._ESCAPED_AS_HEX:
            # Convert the character into its utf-8 hex representation
            hex_string = binascii.hexlify(char.encode("utf-8")).decode("utf-8")
            if len(hex_string) % 2 == 1:
                raise DecodingError("Even number of elements expected.")
            pairs = [lead + trail for lead, trail in zip(hex_string[::2], hex_string[1::2])]
            # The hex representation is escaped by a '\' every two hex digits.
            value = value.replace(char, cls._ESCAPE + cls._ESCAPE.join(pairs))
        return value

    @classmethod
    def _unescape_hexstring(cls, value: str) -> bytes:
        """Remove escaping from the string representation.

        This function may only unescape values in hexstring form. For values in string
        form, use _unescape_string instead.
        For details, see Sec. 3 [RFC4514].
        """
        if not cls.is_hexstring(value):
            raise RuntimeError
        return binascii.unhexlify(value.lstrip("#"))

    @classmethod
    def _unescape_string(cls, value: str) -> str:
        """Remove escaping from the string representation.

        This function may only unescape values in string form. For values in hexstring
        form, use _unescape_hexstring instead.
        For details, see Sec. 3 [RFC4514].
        """
        if cls.is_hexstring(value):
            raise RuntimeError
        # We may encounter two kinds of escaped values:
        # - <ESC><special>, where <special> is a member of _ESCAPE_LEADING,
        #   _ESCAPE_TRAILING or _ESCAPE_EVERYWHERE
        # - <ESC><hexpair>, where <hexpair> are two hex digits, representing the utf-8
        #   encoded value of (part of) an utf-8 character.
        # To ensure the latter is translated correctly (one character may be encoded by
        # more than one <ESC><hexpair>!), we encode the whole string in utf-8 and
        # decode it back at the very end. This delegates the proper decoding of the
        # <hexpair> octets to python.
        utf8_bytes = b""
        itr: Iterator[str] = iter(value)
        for char in itr:
            # shortcircuit the default case
            if char != cls._ESCAPE:
                try:
                    utf8_bytes += char.encode("utf-8")
                except UnicodeEncodeError as e:
                    raise DecodingError from e
                continue
            # if char is <ESC>
            try:
                next_char = next(itr)
            except StopIteration as e:
                raise DecodingError from e
            # replace <ESC><hexpair> with the octet indicated by the <hexpair>
            if next_char in HEXDIGITS:
                try:
                    next_next_char = next(itr)
                except StopIteration as e:
                    raise DecodingError from e
                if next_next_char in HEXDIGITS:
                    try:
                        utf8_bytes += binascii.unhexlify(
                            (next_char + next_next_char).encode("utf-8"))
                    except UnicodeEncodeError as e:
                        raise DecodingError from e
                else:
                    raise DecodingError
            # replace <ESC><ESC> with <ESC>
            # replace <ESC><special> with <special>
            else:
                try:
                    utf8_bytes += next_char.encode("utf-8")
                except UnicodeEncodeError as e:
                    raise DecodingError from e
        # finally, decode the bytes back into an utf-8 string
        try:
            ret = utf8_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise DecodingError from e
        return ret


class DistinguishedName:
    # TODO sorting of rdns should be from root to leaf, not the other way round
    rdns: List[RelativeDistinguishedName]

    def __init__(
        self,
        raw: Union[str, RelativeDistinguishedName, Sequence[RelativeDistinguishedName]]
    ) -> None:
        self.rdns = []
        if isinstance(raw, str):
            self.rdns.extend(
                RelativeDistinguishedName(rdn) for rdn in escaped_split(raw, delim=","))
        elif isinstance(raw, RelativeDistinguishedName):
            self.rdns.append(raw)
        else:
            self.rdns.extend(raw)

    def __str__(self) -> str:
        return self.string

    @property
    def string(self) -> str:
        """The (escaped) string representation of the DN."""
        return ",".join(rdn.string for rdn in self.rdns)


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


def is_numericoid(value: str) -> bool:
    """Check if the given value is a numericoid.

    The numericoid sequence is defined in Sec. 1.4 [RFC4512]:
    numericoid = number 1*( DOT number )
    """
    return all(components.isdecimal() for components in value.split("."))


# LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
#            -- [RFC4512]
class LDAPOID(BEROctetString):
    value: str  # type: ignore[assignment]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPOID":
        try:
            utf8 = content.decode("utf-8")
        except UnicodeDecodeError as e:
            raise DecodingError from e
        return cls(utf8)

    def __init__(self, value: str):
        # validate the given value to be a numericoid
        if not is_numericoid(value):
            raise ValueError(f"Given value is no valid numericoid: {value}")
        super().__init__(value)  # type: ignore[arg-type]

    def to_wire(self) -> bytes:
        try:
            encoded = self.value.encode("utf-8")
        except UnicodeEncodeError as e:
            raise EncodingError from e
        return bytes((self.tag,)) + berlen(encoded) + encoded


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
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])
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
        return cls(value)

    def __init__(self, value: List[bytes]):
        # Note that we do not check that no two values of an attribute are equivalent.
        # This needs more context than is present here. See [RFC4512], Section 2.2
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
        if len(vals) < 2:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])
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
        if len(values) == 0:
            raise ValueError(f"{self.__class__.__name__} takes at least one value.")
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
