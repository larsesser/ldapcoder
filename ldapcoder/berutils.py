"""Pure, simple, BER encoding and decoding"""

# This BER library is currently aimed at supporting LDAP, thus
# the following restrictions from RFC2251 apply:
#
# (1) Only the definite form of length encoding will be used.
#
# (2) OCTET STRING values will be encoded in the primitive form
#     only.
#
# (3) If the value of a BOOLEAN type is true, the encoding MUST have
#     its contents octets set to hex "FF".
#
# (4) If a value of a type is its default value, it MUST be absent.
#     Only some BOOLEAN and INTEGER types have default values in
#     this protocol definition.
import abc
import enum
import logging
from typing import Any, Callable, List, Sequence, Tuple, Type

from ldapcoder.exceptions import EncodingError, InsufficientDataError

# xxxxxxxx
# |/|\.../
# | | |
# | | tag
# | |
# | primitive (0) or structured (1)
# |
# class

# LENGTH
# 0xxxxxxx = 0..127
# 1xxxxxxx = len is stored in the next 0xxxxxxx octets
# indefinite form not supported
MULTI_BYTE_LENGTH_MASK = 0x80


logger = logging.getLogger(__name__)


def ber_decode_length(m: bytes, offset: int = 0) -> Tuple[int, int]:
    """Extract the length property of a BER element.

    m is the bytes representation of the BER element, where its assumed that m[offset]
    is the first byte which decodes the length property.

    There are two ways to encode the length of an BER object:
    - Single-Byte-Representation: Lengths up to 127 may be encoded directly as the
      binary representation of the number.
    - Multi-Byte-Representation: The most significant bit is set to 1, the remaining
      bits describe how many of the following bytes are used to describe the length.
    """
    l = ber2int(m[offset + 0 : offset + 1], signed=False)
    ll = 1
    if l & MULTI_BYTE_LENGTH_MASK:
        ll = 1 + (l & 0x7F)
        if len(m) < offset + ll:
            raise InsufficientDataError
        l = ber2int(m[offset + 1 : offset + ll], signed=False)
    return (l, ll)


def berlen(content: bytes) -> bytes:
    """Calculate the length of an BER object from its content."""
    encoded = int2ber(len(content), signed=False)
    # Use single-byte-representation
    if len(content) <= 127:
        return encoded
    # use multi-byte-representation
    if len(encoded) > 127:
        raise EncodingError("Object too long to be encoded.")
    return bytes((MULTI_BYTE_LENGTH_MASK | len(encoded),)) + encoded


def int2ber(i: int, signed: bool = True) -> bytes:
    """Encode an integer as BER content.

    This does not add a tag or the length of the BER object.
    """
    encoded = b""
    while (signed and (i > 127 or i < -128)) or (not signed and (i > 255)):
        encoded = bytes((i % 256,)) + encoded
        i = i >> 8
    encoded = bytes((i % 256,)) + encoded
    return encoded


def ber2int(e: bytes, signed: bool = True) -> int:
    """Decode a BER content to an integer.

    The tag and the length of the BER object need to be handled beforehand.
    """
    if len(e) < 1:
        raise InsufficientDataError
    v = 0 + ord(e[0:1])
    if v & 0x80 and signed:
        v = v - 256
    for i in range(1, len(e)):
        v = (v << 8) | ord(e[i : i + 1])
    return v


class ClassProperty(object):
    def __init__(self, fget: Callable[[Any], Any]) -> None:
        self.fget = fget

    def __get__(self, obj: Any, class_: Any = None) -> Any:
        if class_ is None:
            class_ = type(obj)
        return self.fget.__get__(obj, class_)()


@enum.unique
class TagClasses(enum.IntEnum):
    UNIVERSAL = 0x00
    APPLICATION = 0x40
    CONTEXT = 0x80
    PRIVATE = 0xC0


class BERBase(metaclass=abc.ABCMeta):
    _tag_class: TagClasses
    _tag_is_constructed: bool = False
    _tag: int

    @classmethod
    def __tag(cls) -> int:
        constructed = 0x00
        if cls._tag_is_constructed:
            constructed = 0x20
        return cls._tag_class | constructed | cls._tag

    tag = ClassProperty(__tag)

    @abc.abstractmethod
    def __init__(self) -> None:
        raise NotImplementedError

    def __len__(self) -> int:
        return len(self.to_wire())

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, BERBase):
            return NotImplemented
        return self.to_wire() == other.to_wire()

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, BERBase):
            return NotImplemented
        return self.to_wire() != other.to_wire()

    def __hash__(self) -> int:
        return hash(self.to_wire())

    @abc.abstractmethod
    def __repr__(self) -> str:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_wire(cls, content: bytes) -> "BERBase":
        """Create an instance of this class from a binary string.

        This is the default way an instance of this class will be created.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def to_wire(self) -> bytes:
        """Encode the instance of this class to its binary value."""
        raise NotImplementedError


class BERInteger(BERBase):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x02
    value: int

    @classmethod
    def from_wire(cls, content: bytes) -> "BERInteger":
        return cls(ber2int(content))

    def __init__(self, value: int) -> None:
        """Create a new BERInteger object.
        value is an integer.
        """
        self.value = value

    def to_wire(self) -> bytes:
        encoded = int2ber(self.value)
        return bytes((self.tag,)) + berlen(encoded) + encoded

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value})"


class BEROctetString(BERBase):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x04
    value: bytes

    @classmethod
    def from_wire(cls, content: bytes) -> "BEROctetString":
        return cls(content)

    def __init__(self, value: bytes) -> None:
        self.value = value

    def to_wire(self) -> bytes:
        return bytes((self.tag,)) + berlen(self.value) + self.value

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value!r})"


class BERNull(BERBase):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x05
    value = None

    def __init__(self) -> None:
        pass

    @classmethod
    def from_wire(cls, content: bytes) -> "BERNull":
        if len(content) != 0:
            logger.warning(f"Received {cls.__name__} element with content: {content!r}")
        return cls()

    def to_wire(self) -> bytes:
        # BERNull objects carry no content, so their length attribute is 0
        return bytes((self.tag,)) + bytes((0,))

    def __repr__(self) -> str:
        return self.__class__.__name__ + "()"


class BERBoolean(BERBase):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x01
    value: bool

    @classmethod
    def from_wire(cls, content: bytes) -> "BERBoolean":
        return cls(bool(ber2int(content)))

    def __init__(self, value: bool) -> None:
        """Create a new BERInteger object.
        value is an integer.
        """
        self.value = value

    def to_wire(self) -> bytes:
        value = bytes((0xFF,)) if self.value else bytes((0x00,))
        return bytes((self.tag,)) + berlen(value) + value

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value})"


class BEREnumerated(BERBase, metaclass=abc.ABCMeta):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x0A
    value: enum.IntEnum

    @classmethod
    @abc.abstractmethod
    def enum_cls(cls) -> Type[enum.IntEnum]:
        raise NotImplementedError

    @classmethod
    def from_wire(cls, content: bytes) -> "BEREnumerated":
        return cls(cls.enum_cls()(ber2int(content)))

    def __init__(self, value: enum.IntEnum) -> None:
        self.value = value

    def to_wire(self) -> bytes:
        encoded = int2ber(self.value)
        return bytes((self.tag,)) + berlen(encoded) + encoded

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value!r})"


class BERSequence(BERBase, metaclass=abc.ABCMeta):
    _tag_class = TagClasses.UNIVERSAL
    _tag_is_constructed = True
    _tag = 0x10

    def wrap(self, content: Sequence[BERBase]) -> bytes:
        """Helper method to wrap the given BERObjects into a BERSequence."""
        vals = b"".join(x.to_wire() for x in content)
        return bytes((self.tag,)) + berlen(vals) + vals

    @staticmethod
    def unwrap(content: bytes) -> List[Tuple[int, bytes]]:
        """Helper method to unwrap the given BERSequence into (tags, contents)."""
        vals, bytes_used = ber_unwrap(content)
        if bytes_used != len(content):
            raise InsufficientDataError
        return vals


class BERSet(BERSequence, metaclass=abc.ABCMeta):
    _tag_class = TagClasses.UNIVERSAL
    _tag_is_constructed = True
    _tag = 0x11


def ber_unwrap(raw: bytes) -> Tuple[List[Tuple[int, bytes]], int]:
    """Takes a raw BER byte string and returns all of its elements tags and contents.

    This does no attempts to decode the contents into BERObjects.

    :returns: A tuple with two elements. The first element contains a list of all
        objects as tuple with two elements (object tag and object content). The second
        element contains the number of used bytes from the given byte string.
    """
    ret = []
    bytes_used = 0
    while raw:
        # The first two bytes are necessary, since they decode the tag and the length
        if len(raw) < 2:
            raise InsufficientDataError
        tag = ber2int(raw[0:1], signed=False)
        length, lenlen = ber_decode_length(raw, offset=1)

        # ensure all content is present
        if len(raw) < 1 + lenlen + length:
            raise InsufficientDataError
        content = raw[1 + lenlen : 1 + lenlen + length]
        # strip the now used bytes from raw
        raw = raw[1+lenlen+length:]

        ret.append((tag, content))
        bytes_used += 1 + lenlen + length
    return (ret, bytes_used)


# TODO unimplemented classes are below:

# class BERObjectIdentifier(BERBase):
#    tag = 0x06
#    pass

# class BERIA5String(BERBase):
#    tag = 0x16
#    pass

# class BERPrintableString(BERBase):
#    tag = 0x13
#    pass

# class BERT61String(BERBase):
#    tag = 0x14
#    pass

# class BERUTCTime(BERBase):
#    tag = 0x17
#    pass

# class BERBitString(BERBase):
#    tag = 0x03
#    pass
