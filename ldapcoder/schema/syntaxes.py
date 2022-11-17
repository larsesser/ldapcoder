"""Implement the basic LDAP syntax.

The syntax of an LDAP object determines how the bits (octets) can be converted into
a meaningful representation of the object (decoding) and vice versa (encoding).

We make use of pythons builtin-types and some basic libraries to present the objects
in a most convenient way, so the user of the library may deal with it.
"""

import abc
import datetime
from typing import Any, List, Tuple

from ldapcoder.exceptions import DecodingError, EncodingError


# SyntaxDescription = LPAREN WSP
#     numericoid                 ; object identifier
#     [ SP "DESC" SP qdstring ]  ; description
#     extensions WSP RPAREN      ; extensions
class LdapSyntax(metaclass=abc.ABCMeta):
    """Base class of each LDAPSyntax.

    A syntax is something similar like a data type: integer, bytes, string ...
    It determines the procedure of encoding and decoding object values of this data type
    into bytes and from bytes, respectively.

    A syntax does not define comparison rules of a data type, they are separately defined
    via MatchingRules.

    numericoid: The numericoid of this syntax.
    description: A short descriptive string for this syntax.
    """
    numericoid: str = ""
    description: str = ""

    @classmethod
    def decode_value(cls, content: bytes) -> Any:
        """Convert the bytes form of an object value into its pythonic form."""
        raise NotImplementedError

    @classmethod
    def encode_value(cls, value: Any) -> bytes:
        """Convert the pythonic form of an object value into its bytes form."""
        raise NotImplementedError


def decode(value: bytes, codec: str = "utf-8") -> str:
    """Decode value. Raise a DecodingError if something went wrong."""
    try:
        return value.decode(codec)
    except UnicodeDecodeError as e:
        raise DecodingError from e


def encode(value: str, codec: str = "utf-8") -> bytes:
    """Encode value. Raise an EncodingError if something went wrong."""
    try:
        return value.encode(codec)
    except UnicodeEncodeError as e:
        raise EncodingError from e


# ( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )
# Section 3.3.1. of [RFC4517]
# TODO Maybe implement as classmethod of AttributeTypes instead?
class AttributeTypeDescriptionSyntax(LdapSyntax):
    """The ABNF of this syntax is found in ldapcoder.schema.attribute_types.py."""
    numericoid = "1.3.6.1.4.1.1466.115.121.1.3"
    description = "Attribute Type Description"


# ( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )
# BitString    = SQUOTE *binary-digit SQUOTE "B"
# binary-digit = "0" / "1"
# Section 3.3.2. of [RFC4517]
class BitStringSyntax(LdapSyntax):
    """String of binary digits."""
    numericoid = "1.3.6.1.4.1.1466.115.121.1.6"
    description = "Bit String"

    @classmethod
    def decode_value(cls, content: bytes) -> str:
        value = decode(content)
        stripped = value.lstrip("'").rstrip("'B")
        if not all(char in {"0", "1"} for char in stripped):
            raise DecodingError(f"No valid bitstring: {stripped}")
        return stripped

    @classmethod
    def encode_value(cls, value: str) -> bytes:
        if not all(char in {"0", "1"} for char in value):
            raise EncodingError
        return encode(f"'{value}'B")


# ( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )
# Boolean = "TRUE" / "FALSE"
# Section 3.3.3. of [RFC4517]
class BooleanSyntax(LdapSyntax):
    """Either True or False."""
    numericoid = "1.3.6.1.4.1.1466.115.121.1.7"
    description = "Boolean"

    @classmethod
    def decode_value(cls, content: bytes) -> bool:
        value = decode(content)
        if value not in {"TRUE", "FALSE"}:
            raise DecodingError(f"No valid boolean: {value}")
        return True if value == "TRUE" else False

    @classmethod
    def encode_value(cls, value: bool) -> bytes:
        return encode("TRUE" if value else "FALSE")


# ( 1.3.6.1.4.1.1466.115.121.1.11 DESC 'Country String' )
# CountryString  = 2(PrintableCharacter) -- restricted to codes from ISO 3166
# Section 3.3.4. of [RFC4517]
class CountryStringSyntax(LdapSyntax):
    """Country codes as described in ISO 3166."""
    numericoid = "1.3.6.1.4.1.1466.115.121.1.11"
    description = "Country String"

    @classmethod
    def decode_value(cls, content: bytes) -> str:
        value = decode(content)
        if len(value) != 2:
            raise DecodingError(f"No valid country string: {value}")
        # TODO add further checks regarding ISO 3166?
        return value

    @classmethod
    def encode_value(cls, value: str) -> bytes:
        if len(value) != 2:
            raise EncodingError(f"No valid country string: {value}")
        # TODO add further checks regarding ISO 3166?
        return encode(value)


# ( 1.3.6.1.4.1.1466.115.121.1.14 DESC 'Delivery Method' )
#  DeliveryMethod = pdm *( WSP DOLLAR WSP pdm )
#  pdm = "any" / "mhs" / "physical" / "telex" / "teletex" / "g3fax" / "g4fax" / "ia5" /
#        "videotex" / "telephone"
# Section 3.3.5. of [RFC4517]
class DeliveryMethodSyntax(LdapSyntax):
    """Service(s) by which an entity is willing and/or capable of receiving messages,
       ordered by preference."""
    numericoid = "1.3.6.1.4.1.1466.115.121.1.14"
    description = "Delivery Method"
    methods = {"any", "mhs", "physical", "telex", "teletex", "g3fax", "g4fax", "ia5",
               "videotex", "telephone"}

    @classmethod
    def decode_value(cls, content: bytes) -> List[str]:
        value = decode(content)
        methods = [method.strip() for method in value.split("$")]
        if len(methods) != len(set(methods)):
            raise DecodingError(f"Delivery methods must be unique: {methods}")
        if any(method not in cls.methods for method in methods):
            raise DecodingError(f"Some delivery methods are unrecognized: {methods}")
        return methods

    @classmethod
    def encode_value(cls, value: List[str]) -> bytes:
        if len(value) != len(set(value)):
            raise EncodingError(f"Delivery methods must be unique: {value}")
        if any(method not in cls.methods for method in value):
            raise EncodingError(f"Some delivery methods are unrecognized: {value}")
        return encode(" $ ".join(value))


# ( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )
# Section 3.3.6. of [RFC4517]
class DirectoryStringSyntax(LdapSyntax):
    """Arbitrary, non-empty string."""
    numericoid = "1.3.6.1.4.1.1466.115.121.1.15"
    description = "Directory String"

    @classmethod
    def decode_value(cls, content: bytes) -> str:
        value = decode(content)
        if value == "":
            raise DecodingError("Empty strings are not allowed.")
        return value

    @classmethod
    def encode_value(cls, value: str) -> bytes:
        if value == "":
            raise EncodingError("Empty strings are not allowed.")
        return encode(value)


# ( 1.3.6.1.4.1.1466.115.121.1.16 DESC 'DIT Content Rule Description' )
# Section 3.3.7. of [RFC4517]
class DitContentRuleDescriptionSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.16"
    description = "DIT Content Rule Description"


# ( 1.3.6.1.4.1.1466.115.121.1.17 DESC 'DIT Structure Rule Description' )
# Section 3.3.8. of [RFC4517]
class DitStructureRuleDescriptionSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.17"
    description = "DIT Structure Rule Description"


# ( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )
# Section 3.3.9. of [RFC4517]
class DnSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.12"
    description = "DN"


# ( 1.3.6.1.4.1.1466.115.121.1.21 DESC 'Enhanced Guide' )
# Section 3.3.10. of [RFC4517]
class EnhancedGuideSyntax(LdapSyntax):
    """Suggests criteria to construct filters to search entries of particular object classes.

    Successor of GuideSyntax.
    """
    numericoid = "1.3.6.1.4.1.1466.115.121.1.21"
    description = "Enhanced Guide"


# ( 1.3.6.1.4.1.1466.115.121.1.22 DESC 'Facsimile Telephone Number')
# fax-number       = telephone-number *( DOLLAR fax-parameter )
# telephone-number = PrintableString
# fax-parameter    = "twoDimensional" / "fineResolution" / "unlimitedLength" /
#                    "b4Length" / "a3Width" / "b4Width" / "uncompressed"
# Section 3.3.11. of [RFC4517]
class FacsimileTelephoneNumberSyntax(LdapSyntax):
    """A subscriber number of a facsimile device on the public switched telephone network.

    The <telephone-number> string complies with the international telephone numbers
    format [E.123].
    """
    numericoid = "1.3.6.1.4.1.1466.115.121.1.22"
    description = "Facsimile Telephone Number"
    fax_parameters = {"twoDimensional", "fineResolution", "unlimitedLength",
                      "b4Length", "a3Width", "b4Width", "uncompressed"}

    @classmethod
    def decode_value(cls, content: bytes) -> Tuple[str, List[str]]:
        value = decode(content)
        splitted = value.split("$")
        tel_number = splitted[0]
        # TODO validate telephone number
        if len(splitted) == 1:
            return (tel_number, [])
        params = splitted[1:]
        if any(param not in cls.fax_parameters for param in params):
            raise DecodingError(f"Some fax parameters are unrecognized: {params}")
        return (tel_number, params)

    @classmethod
    def encode_value(cls, value: Tuple[str, List[str]]) -> bytes:
        tel_number, params = value
        # TODO validate telephone number
        if any(param not in cls.fax_parameters for param in params):
            raise EncodingError(f"Some fax parameters are unrecognized: {params}")
        return encode("$".join([tel_number, *params]))


# ( 1.3.6.1.4.1.1466.115.121.1.23 DESC 'Fax' )
# Section 3.3.12. of [RFC4517]
class FaxSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.23"
    description = "Fax"


# GeneralizedTime = century year month day hour
#                      [ minute [ second / leap-second ] ]
#                      [ fraction ]
#                      g-time-zone
#
# century = 2(%x30-39) ; "00" to "99"
# year    = 2(%x30-39) ; "00" to "99"
# month   =   ( %x30 %x31-39 ) ; "01" (January) to "09"
#           / ( %x31 %x30-32 ) ; "10" to "12"
# day     =   ( %x30 %x31-39 )    ; "01" to "09"
#           / ( %x31-32 %x30-39 ) ; "10" to "29"
#           / ( %x33 %x30-31 )    ; "30" to "31"
# hour    = ( %x30-31 %x30-39 ) / ( %x32 %x30-33 ) ; "00" to "23"
# minute  = %x30-35 %x30-39                        ; "00" to "59"
#
# second      = ( %x30-35 %x30-39 ) ; "00" to "59"
# leap-second = ( %x36 %x30 )       ; "60"
# fraction        = ( DOT / COMMA ) 1*(%x30-39)
#
# g-time-zone     = %x5A  ; "Z" / g-differential
# g-differential  = ( MINUS / PLUS ) hour [ minute ]
# MINUS           = %x2D  ; minus sign ("-")
# Section 3.3.13. of [RFC4517]
def generalizedtime_to_datetime(value: str) -> datetime.datetime:
    """Convert a generalized time object to a datetime object.

    The conversion is exact, with exception to leap seconds which are not supported
    by datetime.
    """
    # the first 10 letters are mandatory (century, year, month, day, hour)
    if len(value) < 10:
        raise ValueError("No valid generalized time object.")
    century = value[0:2]
    year = value[2:4]
    month = value[4:6]
    day = value[6:8]
    hour = value[8:10]
    if any(not val.isdigit() for val in [century, year, month, day, hour]):
        raise ValueError("No valid generalized time object.")
    value = value[10:]

    # search and separate the g-time-zone from the end of the string
    if value.endswith("Z"):
        value = value[:-1]
        timezone = "+0000"
    elif len(value.split("+")) == 2:
        value, timezone = value.split("+")
        timezone = "+" + timezone
    elif len(value.split("-")) == 2:
        value, timezone = value.split("-")
        timezone = "-" + timezone
    else:
        raise ValueError("No valid g-time-zone part")
    if not timezone[1:].isdigit():
        raise ValueError("Invalid timezone.")

    # pad the timezone part with 00 for minutes and insert a : between hours and minutes
    if len(timezone) == 3:
        timezone = timezone + "00"
    elif len(timezone) == 5:
        timezone = timezone[0:3] + ":" + timezone[3:5]
    else:
        raise ValueError("No valid g-time-zone part")

    # now we come to the optional parts: minute, second, fraction
    # Fractions of seconds will lead to microseconds.
    microsecond = 0
    if len(value) == 0:
        minute = "00"
        second = "00"
    # there is a fraction present
    elif "." in value or "," in value:
        # fraction of hours
        if (value.startswith(".") or value.startswith(",")) and len(value) == 2:
            fraction = value[-1]
            if not fraction.isdigit():
                raise ValueError("No valid generalized time object.")
            # pad the minute with zeros to 2 digits
            minute = f"{int(fraction)*6:0>2}"
            second = "00"
        # fraction of minutes
        elif len(value) == 4:
            minute = value[0:2]
            fraction = value[-1]
            if not fraction.isdigit():
                raise ValueError("No valid generalized time object.")
            # pad the second with zeros to 2 digits
            second = f"{int(fraction) * 6:0>2}"
        # fraction of seconds
        elif len(value) == 6:
            minute = value[0:2]
            second = value[2:4]
            fraction = value[-1]
            if not fraction.isdigit():
                raise ValueError("No valid generalized time object.")
            microsecond = int(fraction) * 10e5
        else:
            raise ValueError("No valid generalized time object.")
    else:
        if len(value) == 2:
            minute = value
            second = "00"
        elif len(value) == 4:
            minute = value[0:2]
            second = value[2:4]
        else:
            raise ValueError("No valid generalized time object.")
    if any(not val.isdigit() for val in [minute, second]):
        raise ValueError("No valid generalized time object.")

    # sadly, datetime can not parse leap seconds...
    if second == "60":
        second = "59"

    datetime_str = f"{century}{year}-{month}-{day}T{hour}:{minute}:{second}{timezone}"
    datetime_object = datetime.datetime.fromisoformat(datetime_str)

    # replace the microseconds
    datetime_object.replace(microsecond=microsecond)
    return datetime_object


def datetime_to_generalizedtime(value: datetime.datetime) -> str:
    # extract the timezone info
    offset = value.utcoffset()
    if offset is None:
        raise ValueError("No timezone info provided.")
    # if offset:
    #     tzprefix = "+"
    #     if offset.days == -1:
    #         offset = -offset
    #         tzprefix = "-"
    #     hours = offset.seconds // 60 // 60
    #     offset = offset - datetime.timedelta(hours=hours)
    #     minutes = offset.seconds // 60
    #     offset = offset - datetime.timedelta(minutes=minutes)
    #     if offset:
    #         raise ValueError("Timezone info is restricted to minutes.")
    #     timezone = f"{tzprefix}{hours}{minutes}"
    # # timezone is UTC
    # else:
    #     timezone = "Z"
    #
    # The "Z" form of <g-time-zone> SHOULD be used in preference to <g-differential>,
    # accordingly to [RFC4517]
    value -= offset
    timezone = "Z"
    # format the generalized time object
    return f"{value.year}{value.month}{value.day}{value.hour}{value.minute}{value.second}{timezone}"


# ( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )
# Section 3.3.13. of [RFC4517]
class GeneralizedTimeSyntax(LdapSyntax):
    """Representation of a date and time.

    The syntax is a restricted variant of [ISO8601].
    """
    numericoid = "1.3.6.1.4.1.1466.115.121.1.24"
    description = "Generalized Time"

    @classmethod
    def decode_value(cls, content: bytes) -> datetime.datetime:
        value = decode(content)
        try:
            datetime_obj = generalizedtime_to_datetime(value)
        except ValueError as e:
            raise DecodingError from e
        return datetime_obj

    @classmethod
    def encode_value(cls, value: datetime.datetime) -> bytes:
        try:
            generalized_time = datetime_to_generalizedtime(value)
        except ValueError as e:
            raise EncodingError from e
        return encode(generalized_time)


# ( 1.3.6.1.4.1.1466.115.121.1.25 DESC 'Guide' )
# Guide = [ object-class SHARP ] criteria
# Section 3.3.14. of [RFC4517]
class GuideSyntax(LdapSyntax):
    """Suggests criteria to construct filters to search entries of particular object classes.

    Deprecated, EnhancedGuideSyntax shall be used instead.
    """
    numericoid = "1.3.6.1.4.1.1466.115.121.1.25"
    description = "Guide"


# ( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )
# IA5String = *(%x00-7F)
# Section 3.3.15. of [RFC4517]
class IA5StringSyntax(LdapSyntax):
    """String of zero, one, or more characters from International Alphabet 5 (IA5).

    This is the international version of the ASCII character set.
    """
    numericoid = "1.3.6.1.4.1.1466.115.121.1.26"
    description = "IA5 String"

    @classmethod
    def decode_value(cls, content: bytes) -> str:
        return decode(content, codec="ascii")

    @classmethod
    def encode_value(cls, value: str) -> bytes:
        return encode(value, codec="ascii")


# ( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'INTEGER' )
# Integer = ( HYPHEN LDIGIT *DIGIT ) / number
# Section 3.3.16. of [RFC4517]
class IntegerSyntax(LdapSyntax):
    """A whole number of unlimited magnitude."""
    numericoid = "1.3.6.1.4.1.1466.115.121.1.27"
    description = "INTEGER"

    @classmethod
    def decode_value(cls, content: bytes) -> int:
        try:
            value = int(decode(content))
        except ValueError as e:
            raise DecodingError from e
        return value

    @classmethod
    def encode_value(cls, value: int) -> bytes:
        return encode(str(value))


# ( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' )
# JPEG ::= OCTET STRING (CONSTRAINED BY
#              { -- contents octets are an image in the --
#                -- JPEG File Interchange Format -- })
# Section 3.3.17. of [RFC4517]
class JPEGSyntax(LdapSyntax):
    """An image in the JPEG File Interchange Format (JFIF)."""
    numericoid = "1.3.6.1.4.1.1466.115.121.1.28"
    description = "JPEG"


# ( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )
# LDAPSyntaxDescription ::= SEQUENCE {
#           identifier      OBJECT IDENTIFIER,
#           description     DirectoryString { ub-schema } OPTIONAL }
# Section 3.3.18. of [RFC4517]
class SyntaxDescriptionSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.54"
    description = "LDAP Syntax Description"


# ( 1.3.6.1.4.1.1466.115.121.1.30 DESC 'Matching Rule Description' )
# Section 3.3.19. of [RFC4517]
class MatchingRuleDescriptionSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.30"
    description = "Matching Rule Description"


# ( 1.3.6.1.4.1.1466.115.121.1.31 DESC 'Matching Rule Use Description' )
# Section 3.3.20. of [RFC4517]
class MatchingRuleUseDescriptionSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.31"
    description = "Matching Rule Use Description"


# ( 1.3.6.1.4.1.1466.115.121.1.34 DESC 'Name And Optional UID' )
# NameAndOptionalUID = distinguishedName [ SHARP BitString ]
# Section 3.3.21. of [RFC4517]
class NameAndOptionalUidSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.34"
    description = "Name And Optional UID"


# ( 1.3.6.1.4.1.1466.115.121.1.35 DESC 'Name Form Description' )
# Section 3.3.22. of [RFC4517]
class NameFormDescriptionSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.35"
    description = "Name Form Description"


# ( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'Numeric String' )
# Section 3.3.23. of [RFC4517]
class NumericStringSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.36"
    description = "Numeric String"


# ( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )
# Section 3.3.24. of [RFC4517]
class ObjectClassDescriptionSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.37"
    description = "Object Class Description"


# ( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )
# Section 3.3.25. of [RFC4517]
class OctetStringSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.40"
    description = "Octet String"


# ( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )
# Section 3.3.26. of [RFC4517]
class OidSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.38"
    description = "OID"


# ( 1.3.6.1.4.1.1466.115.121.1.39 DESC 'Other Mailbox' )
# OtherMailbox ::= SEQUENCE {
#      mailboxType  PrintableString,
#      mailbox      IA5String
# }
# Section 3.3.27. of [RFC4517]
class OtherMailboxSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.39"
    description = "Other Mailbox"


# ( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'Postal Address' )
# PostalAddress = line *( DOLLAR line )
# line          = 1*line-char
# line-char     = %x00-23
#                 / (%x5C "24")  ; escaped "$"
#                 / %x25-5B
#                 / (%x5C "5C")  ; escaped "\"
#                 / %x5D-7F
#                 / UTFMB
# Section 3.3.28. of [RFC4517]
class PostalAddressSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.41"
    description = "Postal Address"


# ( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )
# Section 3.3.29. of [RFC4517]
class PrintableStringSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.44"
    description = "Printable String"


# ( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring Assertion' )
# SubstringAssertion = [ initial ] any [ final ]
#
# initial  = substring
# any      = ASTERISK *(substring ASTERISK)
# final    = substring
# ASTERISK = %x2A  ; asterisk ("*")
#
# substring           = 1*substring-character
# substring-character = %x00-29
#                       / (%x5C "2A")  ; escaped "*"
#                       / %x2B-5B
#                       / (%x5C "5C")  ; escaped "\"
#                       / %x5D-7F
#                       / UTFMB
# Section 3.3.30. of [RFC4517]
class SubstringAssertionSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.58"
    description = "Substring Assertion"


# ( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )
# Section 3.3.31. of [RFC4517]
class TelephoneNumberSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.50"
    description = "Telephone Number"


# ( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )
# teletex-id = ttx-term *(DOLLAR ttx-param)
# ttx-term   = PrintableString          ; terminal identifier
# ttx-param  = ttx-key COLON ttx-value  ; parameter
# ttx-key    = "graphic" / "control" / "misc" / "page" / "private"
# ttx-value  = *ttx-value-octet
#
# ttx-value-octet = %x00-23
#                   / (%x5C "24")  ; escaped "$"
#                   / %x25-5B
#                   / (%x5C "5C")  ; escaped "\"
#                   / %x5D-FF
# Section 3.3.32. of [RFC4517]
class TeletextTerminalIdentifierSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.51"
    description = "Teletex Terminal Identifier"


# ( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'Telex Number' )
# telex-number  = actual-number DOLLAR country-code
#                    DOLLAR answerback
# actual-number = PrintableString
# country-code  = PrintableString
# answerback    = PrintableString
# Section 3.3.33. of [RFC4517]
class TelexNumberSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.52"
    description = "Telex Number"


# ( 1.3.6.1.4.1.1466.115.121.1.53 DESC 'UTC Time' )
# UTCTime         = year month day hour minute [ second ]
#                      [ u-time-zone ]
# u-time-zone     = %x5A  ; "Z"
#                   / u-differential
# u-differential  = ( MINUS / PLUS ) hour minute
# Section 3.3.34. of [RFC4517]
class UtcTimeSyntax(LdapSyntax):
    numericoid = "1.3.6.1.4.1.1466.115.121.1.53"
    description = "UTC Time"
