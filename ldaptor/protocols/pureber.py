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
from typing import Tuple, List, Type, Sequence

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


class UnknownBERTag(Exception):
    def __init__(self, tag):
        Exception.__init__(self)
        self.tag = tag

    def __str__(self):
        return "BERDecoderContext has no tag 0x{:02x}".format(
            self.tag
        )


def berDecodeLength(m: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Return a tuple of (length, lengthLength).
    m must be atleast one byte long.
    """
    l = ber2int(m[offset + 0 : offset + 1])
    ll = 1
    if l & 0x80:
        ll = 1 + (l & 0x7F)
        need(m, offset + ll)
        l = ber2int(m[offset + 1 : offset + ll], signed=False)
    return (l, ll)


def int2berlen(i: int) -> bytes:
    assert i >= 0
    e = int2ber(i, signed=False)
    if i <= 127:
        return e
    else:
        l = len(e)
        assert l > 0
        assert l <= 127
        return bytes((0x80 | l,)) + e


def int2ber(i: int, signed: bool = True) -> bytes:
    encoded = b""
    while (signed and (i > 127 or i < -128)) or (not signed and (i > 255)):
        encoded = bytes((i % 256,)) + encoded
        i = i >> 8
    encoded = bytes((i % 256,)) + encoded
    return encoded


def ber2int(e: bytes, signed: bool = True) -> int:
    need(e, 1)
    v = 0 + ord(e[0:1])
    if v & 0x80 and signed:
        v = v - 256
    for i in range(1, len(e)):
        v = (v << 8) | ord(e[i : i + 1])
    return v


class ClassProperty(object):
    def __init__(self, fget):
        self.fget = fget

    def __get__(self, obj, class_=None):
        if class_ is None:
            class_ = type(obj)
        return self.fget.__get__(obj, class_)()


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
    def __init__(self):
        raise NotImplementedError

    def __len__(self):
        return len(self.to_wire())

    def __eq__(self, other):
        if not isinstance(other, BERBase):
            return NotImplemented
        return self.to_wire() == other.to_wire()

    def __ne__(self, other):
        if not isinstance(other, BERBase):
            return NotImplemented

        return self.to_wire() != other.to_wire()

    def __hash__(self):
        return hash(self.to_wire())

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


class BERExceptionInsufficientData(Exception):
    pass


def need(buf: bytes, n: int) -> None:
    d = n - len(buf)
    if d > 0:
        raise BERExceptionInsufficientData(d)


class BERInteger(BERBase):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x02
    value: int

    @classmethod
    def from_wire(cls, content: bytes) -> "BERInteger":
        assert len(content) > 0
        return cls(ber2int(content))

    def __init__(self, value: int):
        """Create a new BERInteger object.
        value is an integer.
        """
        assert value is not None
        self.value = value

    def to_wire(self):
        encoded = int2ber(self.value)
        return bytes((self.tag,)) + int2berlen(len(encoded)) + encoded

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%r)" % self.value
        else:
            return self.__class__.__name__ + "(value=%r, tag=%d)" % (
                self.value,
                self.tag,
            )


class BEROctetString(BERBase):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x04
    value: bytes

    @classmethod
    def from_wire(cls, content: bytes) -> "BEROctetString":
        assert len(content) >= 0
        return cls(content)

    def __init__(self, value: bytes,):
        assert value is not None
        self.value = value

    def to_wire(self):
        return bytes((self.tag,)) + int2berlen(len(self.value)) + self.value

    def __repr__(self):
        value = self.value
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(value)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(value),
                self.tag,
            )


class BERNull(BERBase):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x05
    value = None

    def __init__(self):
        pass

    @classmethod
    def from_wire(cls, content: bytes) -> "BERNull":
        assert len(content) == 0
        return cls()

    def to_wire(self):
        return bytes((self.tag,)) + bytes((0,))

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "()"
        else:
            return self.__class__.__name__ + "(tag=%d)" % self.tag


class BERBoolean(BERBase):
    _tag_class = TagClasses.UNIVERSAL
    _tag = 0x01
    value: bool

    @classmethod
    def from_wire(cls, content: bytes) -> "BERBoolean":
        assert len(content) > 0
        return cls(bool(ber2int(content)))

    def __init__(self, value: bool):
        """Create a new BERInteger object.
        value is an integer.
        """
        assert value is not None
        self.value = value

    def to_wire(self):
        value = 0xFF if self.value else 0x00
        return bytes((self.tag,)) + int2berlen(1) + bytes((value,))

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%d)" % self.value
        else:
            return self.__class__.__name__ + "(value=%d, tag=%d)" % (
                self.value,
                self.tag,
            )


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
        assert len(content) > 0
        return cls(cls.enum_cls()(ber2int(content)))

    def __init__(self, value: enum.IntEnum):
        assert value is not None
        self.value = value

    def to_wire(self):
        encoded = int2ber(self.value)
        return bytes((self.tag,)) + int2berlen(len(encoded)) + encoded

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%r)" % self.value
        else:
            return self.__class__.__name__ + "(value=%r, tag=%d)" % (
                self.value,
                self.tag,
            )


class BERSequence(BERBase, metaclass=abc.ABCMeta):
    _tag_class = TagClasses.UNIVERSAL
    _tag_is_constructed = True
    _tag = 0x10

    def wrap(self, content: Sequence[BERBase]) -> bytes:
        """Helper method to wrap the given BERObjects into a BERSequence."""
        vals = b"".join(x.to_wire() for x in content)
        return bytes((self.tag,)) + int2berlen(len(vals)) + vals

    @staticmethod
    def unwrap(content: bytes) -> List[Tuple[int, bytes]]:
        """Helper method to unwrap the given BERSequence into (tags, contents)."""
        vals, bytes_used = berUnwrap(content)
        if bytes_used != len(content):
            raise BERExceptionInsufficientData
        return vals


class BERSet(BERSequence, metaclass=abc.ABCMeta):
    _tag_class = TagClasses.UNIVERSAL
    _tag_is_constructed = True
    _tag = 0x11


def berUnwrap(raw: bytes) -> Tuple[List[Tuple[int, bytes]], int]:
    """Takes a raw ber byte string and returns all of its elements tags and contents.

    This does no attempts to decode the contents into an BERObjects.

    :returns: A tuple with two elements. The first element contains a list of all
        objects as tuple with two elements (object tag and objects content). The second
        element contains the number of used bytes from the given byte string.
    """
    ret = []
    bytes_used = 0
    while raw:
        # The first two bytes are necessary, since they decode the tag and the length
        need(raw, 2)
        tag = ber2int(raw[0:1], signed=False)
        length, lenlen = berDecodeLength(raw, offset=1)

        # ensure all content is present
        need(raw, 1 + lenlen + length)
        content = raw[1 + lenlen : 1 + lenlen + length]

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
