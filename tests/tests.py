"""Test the encoding and decoding of hex strings into BER/LDAP objects.

All case samples are generously taken from
https://ldap.com/ldapv3-wire-protocol-reference/
and following subpages.
"""

import binascii
import enum
import unittest
from typing import Type

from ldapcoder.berutils import (
    BERBoolean, BEREnumerated, BERInteger, BERNull, BEROctetString, ber_decode_length,
    ber_unwrap,
)
from ldapcoder.filter import (
    LDAPFilter_and, LDAPFilter_approxMatch, LDAPFilter_equalityMatch,
    LDAPFilter_extensibleMatch, LDAPFilter_greaterOrEqual, LDAPFilter_lessOrEqual,
    LDAPFilter_not, LDAPFilter_or, LDAPFilter_present, LDAPFilter_substrings,
    LDAPFilter_substrings_any, LDAPFilter_substrings_final,
    LDAPFilter_substrings_initial,
)
from ldapcoder.ldaputils import (
    LDAPAttribute, LDAPAttributeValueAssertion, LDAPPartialAttribute,
)
from ldapcoder.message import LDAPControl, LDAPMessage
from ldapcoder.operations.abandon import LDAPAbandonRequest
from ldapcoder.operations.add import LDAPAddRequest, LDAPAddResponse
from ldapcoder.operations.bind import LDAPBindRequest, LDAPBindResponse
from ldapcoder.operations.compare import LDAPCompareRequest, LDAPCompareResponse
from ldapcoder.operations.delete import LDAPDelRequest, LDAPDelResponse
from ldapcoder.operations.modify import (
    LDAPModify_change, LDAPModifyRequest, LDAPModifyResponse, ModifyOperations,
)
from ldapcoder.operations.modify_dn import LDAPModifyDNRequest, LDAPModifyDNResponse
from ldapcoder.operations.unbind import LDAPUnbindRequest
from ldapcoder.result import ResultCodes


def unhexlify(hexstring: str) -> bytes:
    """Enhance binascii's unhexlify function to ignore whitespace, linebreaks and comments."""
    lines = hexstring.split("\n")
    no_comments = [line.split("--")[0] for line in lines]
    no_space = [line.replace(" ", "") for line in no_comments]
    return binascii.unhexlify("".join(no_space))


class MyTests(unittest.TestCase):
    def first_level_unwrap(self, val: bytes, expected_tag: int) -> bytes:
        """Decode tag and length of the outermost BER/LDAP object."""
        first_level, bytes_used = ber_unwrap(val)
        self.assertEqual(len(val), bytes_used)
        self.assertEqual(1, len(first_level))
        tag, content = first_level[0]
        self.assertEqual(expected_tag, tag)
        return content

    def test_BERLength(self):
        """All cases encode a length of 10."""
        cases = ["0a", "81 0a", "82 00 0a", "84 00 00 00 0a",
                 "8a 00 00 00 00 00 00 00 00 00 0a"]
        for case in cases:
            self.assertEqual(
                (10, len(case.split(" "))), ber_decode_length(unhexlify(case)))

    def test_BERNull(self):
        case = "05 00"
        content = self.first_level_unwrap(unhexlify(case), BERNull.tag)
        result = BERNull.from_wire(content)
        self.assertEqual(BERNull(), result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_BERBoolean(self):
        cases = {True: "01 01 ff", False: "01 01 00"}
        for expectation, case in cases.items():
            content = self.first_level_unwrap(unhexlify(case), BERBoolean.tag)
            result = BERBoolean.from_wire(content)
            self.assertEqual(BERBoolean(expectation), result)
            self.assertEqual(unhexlify(case), result.to_wire())

    def test_BEROctetString(self):
        case = "04 06 48 65 6c 6c 6f 21"
        content = self.first_level_unwrap(unhexlify(case), BEROctetString.tag)
        result = BEROctetString.from_wire(content)
        self.assertEqual(BEROctetString(unhexlify("48 65 6c 6c 6f 21")), result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_BERInteger(self):
        cases = {0: "02 01 00", 50: "02 01 32", 50000: "02 03 00 c3 50",
                 -12345: "02 02 cf c7"}
        for expectation, case in cases.items():
            content = self.first_level_unwrap(unhexlify(case), BERInteger.tag)
            result = BERInteger.from_wire(content)
            self.assertEqual(BERInteger(expectation), result)
            self.assertEqual(unhexlify(case), result.to_wire())

    def test_BEREnumerated(self):
        class ExampleEnum(enum.IntEnum):
            cool = 0
            uncool = 10

        class ExampleEnumerated(BEREnumerated):
            @classmethod
            def enum_cls(cls) -> Type[enum.IntEnum]:
                return ExampleEnum

        cases = {ExampleEnum.cool: "0a 01 00", ExampleEnum.uncool: "0a 01 0a"}
        for expectation, case in cases.items():
            content = self.first_level_unwrap(unhexlify(case), ExampleEnumerated.tag)
            result = ExampleEnumerated.from_wire(content)
            self.assertEqual(ExampleEnumerated(expectation), result)
            self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPMessage(self):
        case = """
30 35 -- Begin the LDAPMessage sequence
    02 01 05 -- The message ID (integer value 5)
    4a 11 64 63 3d 65 78 61 6d 70 -- The delete request protocol op
        6c 65 2c 64 63 3d 63 6f   -- (octet string
        6d                        -- dc=example,dc=com)
    a0 1d -- Begin the sequence for the set of controls
        30 1b -- Begin the sequence for the first control
            04 16 31 2e 32 2e 38 34 30 2e -- The control OID
            31 31 33 35 35 36 2e 31       -- (octet string
            2e 34 2e 38 30 35             -- 1.2.840.113556.1.4.805)
            01 01 ff -- The control criticality (Boolean true)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        operation = LDAPDelRequest("dc=example,dc=com")
        controls = [LDAPControl(controlType=b'1.2.840.113556.1.4.805', criticality=True)]
        expectation = LDAPMessage(msg_id=5, operation=operation, controls=controls)
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPResult_simple(self):
        case = """
30 0c -- Begin the LDAPMessage sequence
    02 01 03 -- The message ID (integer value 3)
    69 07 -- Begin the add response protocol op
        0a 01 00 -- success result code (enumerated value 0)
        04 00 -- No matched DN (0-byte octet string)
        04 00 -- No diagnostic message (0-byte octet string)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=3, operation=LDAPAddResponse(
            ResultCodes.success, matchedDN="", diagnosticMessage=""))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPResult_extended(self):
        case = """
30 81 9d -- Begin the LDAPMessage sequence
    02 01 03 -- The message ID (integer value 3)
    69 81 97 -- Begin the add response protocol op
        0a 01 20 -- noSuchObject result code (enumerated value 32)
        04 1d 6f 75 3d 50 65 6f 70 6c -- Matched DN
            65 2c 20 64 63 3d 65 78   -- (29-byte octet string)
            61 6d 70 6c 65 2c 20 64
            63 3d 63 6f 6d
        04 73 45 6e 74 72 79 20 75 69 -- Diagnostic message
            64 3d 6d 69 73 73 69 6e   -- (115-byte octet string)
            67 31 2c 20 6f 75 3d 6d
            69 73 73 69 6e 67 32 2c
            20 6f 75 3d 50 65 6f 70
            6c 65 2c 20 64 63 3d 65
            78 61 6d 70 6c 65 2c 20
            64 63 3d 63 6f 6d 20 63
            61 6e 6e 6f 74 20 62 65
            20 63 72 65 61 74 65 64
            20 62 65 63 61 75 73 65
            20 69 74 73 20 70 61 72
            65 6e 74 20 64 6f 65 73
            20 6e 6f 74 20 65 78 69
            73 74 2e
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        matchedDN = "ou=People, dc=example, dc=com"
        diagnosticMessage = ("Entry uid=missing1, ou=missing2, ou=People, dc=example,"
                             " dc=com cannot be created because its parent does not exist.")
        expectation = LDAPMessage(msg_id=3, operation=LDAPAddResponse(
            ResultCodes.noSuchObject, matchedDN=matchedDN, diagnosticMessage=diagnosticMessage))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPResult_referral(self):
        case = """
30 81 cf -- Begin the LDAPMessage sequence
    02 01 03 -- The message ID (integer value 3)
    69 81 c9 -- Begin the add response protocol op
        0a 01 0a -- REFERRAL result code (enumerated value 10)
        04 00 -- No matched DN (0-byte octet string)
        04 2f 54 68 69 73 20 73 65 72 -- Diagnostic message
            76 65 72 20 69 73 20 72   -- (47-byte octet string)
            65 61 64 2d 6f 6e 6c 79
            2e 20 20 54 72 79 20 61
            20 64 69 66 66 65 72 65
            6e 74 20 6f 6e 65 2e
        a3 81 90 -- Begin the referrals sequence
            04 46 6c 64 61 70 3a 2f 2f 61 -- First referral URL
                6c 74 65 72 6e 61 74 65   -- (70-byte octet string)
                31 2e 65 78 61 6d 70 6c
                65 2e 63 6f 6d 3a 33 38
                39 2f 75 69 64 3d 6a 64
                6f 65 2c 6f 75 3d 52 65
                6d 6f 74 65 2c 64 63 3d
                65 78 61 6d 70 6c 65 2c
                64 63 3d 63 6f 6d
            04 46 6c 64 61 70 3a 2f 2f 61 -- Second referral URL
                6c 74 65 72 6e 61 74 65   -- (70-byte octet string)
                32 2e 65 78 61 6d 70 6c
                65 2e 63 6f 6d 3a 33 38
                39 2f 75 69 64 3d 6a 64
                6f 65 2c 6f 75 3d 52 65
                6d 6f 74 65 2c 64 63 3d
                65 78 61 6d 70 6c 65 2c
                64 63 3d 63 6f 6d
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        diagnosticMessage = "This server is read-only.  Try a different one."
        referral = [
            "ldap://alternate1.example.com:389/uid=jdoe,ou=Remote,dc=example,dc=com",
            "ldap://alternate2.example.com:389/uid=jdoe,ou=Remote,dc=example,dc=com"]
        expectation = LDAPMessage(msg_id=3, operation=LDAPAddResponse(
            ResultCodes.referral, matchedDN="", diagnosticMessage=diagnosticMessage,
            referral=referral))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPAbandonRequest(self):
        case = """
30 06 -- Begin the LDAPMessage sequence
    02 01 06 -- The message ID (integer value 6)
    50 01 05 -- The abandon request protocol op (application primitive integer 5)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=6, operation=LDAPAbandonRequest(value=5))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPAddRequest(self):
        case = """
30 49 -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    68 44 -- Begin the add request protocol op
        04 11 64 63 3d 65 78 61 6d 70 -- The DN of the entry to add
            6c 65 2c 64 63 3d 63 6f   -- (octet string "dc=example,dc=com")
            6d
        30 2f -- Begin the sequence of attributes
            30 1c -- Begin the first attribute sequence
                04 0b 6f 62 6a 65 63 74 43 6c -- The attribute description
                61 73 73                      -- (octet string "objectClass")
                31 0d -- Begin the set of values
                    04 03 74 6f 70 -- The first value (octet string "top")
                    04 06 64 6f 6d 61 69 6e -- The second value (octet string "domain")
            30 0f -- Begin the second attribute sequence
                04 02 64 63 -- The attribute description (octet string "dc")
                31 09 -- Begin the set of values
                    04 07 65 78 61 6d 70 6c 65 -- The value (octet string "example")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        attributes = [LDAPAttribute(type_="objectClass", values=[b"top", b"domain"]),
                      LDAPAttribute(type_="dc", values=[b"example"])]
        add = LDAPAddRequest(entry="dc=example,dc=com", attributes=attributes)
        expectation = LDAPMessage(msg_id=2, operation=add)
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPAddResponse(self):
        case = """
30 0c -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    69 07 -- Begin the add response protocol op
        0a 01 00 -- success result code (enumerated value 0)
        04 00 -- No matched DN (0-byte octet string)
        04 00 -- No diagnostic message (0-byte octet string)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPAddResponse(
            resultCode=ResultCodes.success, matchedDN="", diagnosticMessage=""))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPBindRequest_anonymous(self):
        case = """
30 0c -- Begin the LDAPMessage sequence
    02 01 01 --  The message ID (integer value 1)
    60 07 -- Begin the bind request protocol op
        02 01 03 -- The LDAP protocol version (integer value 3)
        04 00 -- Empty bind DN (0-byte octet string)
        80 00 -- Empty password (0-byte octet string with type context-specific
              -- primitive zero)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=1, operation=LDAPBindRequest(
            version=3, dn="", auth=b""))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPBindRequest_simple(self):
        case = """
30 39 -- Begin the LDAPMessage sequence
    02 01 01 -- The message ID (integer value 1)
    60 34 -- Begin the bind request protocol op
    02 01 03 -- The LDAP protocol version (integer value 3)
    04 24 75 69 64 3d 6a 64 6f 65 -- The bind DN (36-byte octet string
        2c 6f 75 3d 50 65 6f 70   -- "uid=jdoe,ou=People,dc=example,dc=com")
        6c 65 2c 64 63 3d 65 78
        61 6d 70 6c 65 2c 64 63
        3d 63 6f 6d
    80 09 73 65 63 72 65 74 31 32 -- The password (9-byte octet string "secret123"
        33                        -- with type context-specific primitive zero)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=1, operation=LDAPBindRequest(
            version=3, dn="uid=jdoe,ou=People,dc=example,dc=com", auth=b"secret123"))
        self.assertEqual(expectation, result)
        self.assertFalse(result.operation.sasl)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPBindResponse_simple(self):
        case = """
30 0c -- Begin the LDAPMessage sequence
    02 01 01 -- The message ID (integer value 1)
    61 07 -- Begin the bind response protocol op
        0a 01 00 -- success result code (enumerated value 0)
        04 00 -- No matched DN (0-byte octet string)
        04 00 -- No diagnostic message (0-byte octet string)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=1, operation=LDAPBindResponse(
            resultCode=ResultCodes.success, matchedDN="", diagnosticMessage=""))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPBindRequest_sasl(self):
        case1 = """
30 16 -- Begin the LDAPMessage sequence
    02 01 01 -- The message ID (integer value 1)
    60 11 -- Begin the bind request protocol op
        02 01 03 -- The LDAP protocol version (integer value 3)
        04 00 -- Empty bind DN (0-byte octet string)
        a3 0a -- Begin the SASL authentication sequence
            04 08 43 52 41 4d 2d 4d 44 35 -- The SASL mechanism name
                                          -- (the octet string "CRAM-MD5")
"""
        content = self.first_level_unwrap(unhexlify(case1), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=1, operation=LDAPBindRequest(
            version=3, dn="", auth=("CRAM-MD5", None)))
        self.assertEqual(expectation, result)
        self.assertTrue(result.operation.sasl)
        self.assertEqual(unhexlify(case1), result.to_wire())

        case2 = """
30 3f -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    60 3a -- Begin the bind request protocol op
        02 01 03 -- The LDAP protocol version (integer value 3)
        04 00 -- Empty bind DN (0-byte octet string)
        a3 33 -- Begin the SASL authentication sequence
            04 08 43 52 41 4d 2d 4d 44 35 -- The SASL mechanism name
                                          -- (the octet string "CRAM-MD5")
            04 27 75 3a 6a 64 6f 65 20 64 -- The SASL credentials (the octet string
            35 32 31 31 36 63 38 37       -- "u:jdoe d52116c87c31d9cc747600f9486d2a1d")
            63 33 31 64 39 63 63 37
            34 37 36 30 30 66 39 34
            38 36 64 32 61 31 64
"""
        content = self.first_level_unwrap(unhexlify(case2), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPBindRequest(
            version=3, dn="", auth=("CRAM-MD5", b"u:jdoe d52116c87c31d9cc747600f9486d2a1d")))
        self.assertEqual(expectation, result)
        self.assertTrue(result.operation.sasl)
        self.assertEqual(unhexlify(case2), result.to_wire())

    def test_LDAPBindResponse_sasl(self):
        case = """
30 30 -- Begin the LDAPMessage sequence
    02 01 01 -- The message ID (integer value 1)
    61 2b -- Begin the bind response protocol op
    0a 01 0e -- saslBindInProgress result code (enumerated value 14)
    04 00 -- No matched DN (0-byte octet string)
    04 00 -- No diagnostic message (0-byte octet string)
    87 22 3c 31 30 61 31 33 63 37 -- The server SASL credentials (the octet string
        62 66 37 30 38 63 61 30 -- "<10a13c7bf708ca0f399ca99e927da88b>")
        66 33 39 39 63 61 39 39
        65 39 32 37 64 61 38 38
        62 3e
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=1, operation=LDAPBindResponse(
            resultCode=ResultCodes.saslBindInProgress, matchedDN="", diagnosticMessage="",
            serverSaslCreds=b"<10a13c7bf708ca0f399ca99e927da88b>"))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPCompareRequest(self):
        case = """
30 45 -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    6e 40 -- Begin the compare request protocol op
    04 24 75 69 64 3d 6a 64 6f 65 -- The target entry DN (octet string
        2c 6f 75 3d 50 65 6f 70 -- "uid=jdoe,ou=People,dc=example,dc=com")
        6c 65 2c 64 63 3d 65 78
        61 6d 70 6c 65 2c 64 63
        3d 63 6f 6d
    30 18 -- Begin the attribute value assertion sequence
        04 0c 65 6d 70 6c 6f 79 65 65 -- The attribute description (octet string
            54 79 70 65               -- "employeeType")
        04 08 73 61 6c 61 72 69 65 64 -- The assertion value (octet string "salaried")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        ava = LDAPAttributeValueAssertion(attributeDesc="employeeType", assertionValue=b"salaried")
        expectation = LDAPMessage(msg_id=2, operation=LDAPCompareRequest(
            entry="uid=jdoe,ou=People,dc=example,dc=com", ava=ava))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPCompareResponse(self):
        case = """
30 0c -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    6f 07 -- Begin the compare response protocol op
        0a 01 06 -- compareTrue result code (enumerated value 6)
        04 00 -- No matched DN (0-byte octet string)
        04 00 -- No diagnostic message (0-byte octet string)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPCompareResponse(
            resultCode=ResultCodes.compareTrue, matchedDN="", diagnosticMessage=""))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPDelRequest(self):
        case = """
30 29 -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    4a 24 75 69 64 3d 6a 64 6f 65 -- The delete request protocol op (octet string
        2c 6f 75 3d 50 65 6f 70   -- "uid=jdoe,ou=People,dc=example,dc=com"
        6c 65 2c 64 63 3d 65 78   -- with type application class, primitive,
        61 6d 70 6c 65 2c 64 63   -- tag number ten)
        3d 63 6f 6d
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPDelRequest(
            "uid=jdoe,ou=People,dc=example,dc=com"))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPDelResponse(self):
        case = """
30 0c -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    6b 07 -- Begin the delete response protocol op
        0a 01 00 -- success result code (enumerated value 0)
        04 00 -- No matched DN (0-byte octet string)
        04 00 -- No diagnostic message (0-byte octet string)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPDelResponse(
            resultCode=ResultCodes.success, matchedDN="", diagnosticMessage=""))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    # TODO LDAPExtendedRequest, LDAPExtendedResponse

    def test_LDAPModifyRequest(self):
        case = """
30 81 80 -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    66 7b -- Begin the modify request protocol op
        04 24 75 69 64 3d 6a 64 6f 65 -- The DN of the entry to modify (octet string
            2c 6f 75 3d 50 65 6f 70   -- "uid=jdoe,ou=People,dc=example,dc=com")
            6c 65 2c 64 63 3d 65 78
            61 6d 70 6c 65 2c 64 63
            3d 63 6f 6d
        30 53 -- Begin the sequence of modifications
            30 18 -- Begin the sequence for the first modification
                0a 01 01 -- The delete modification type (enumerated value 1)
                30 13 -- Begin the attribute sequence
                    04 09 67 69 76 65 6e 4e 61 6d -- The attribute description
                    65                            -- (octet string "givenName")
                    31 06 -- Begin the attribute value set
                        04 04 4a 6f 68 6e -- The attribute value (octet string "John")
            30 1c -- Begin the sequence for the second modification
                0a 01 00 -- The add modification type (enumerated value 0)
                30 17 -- Begin the attribute sequence
                    04 09 67 69 76 65 6e 4e 61 6d -- The attribute description
                    65                            -- (octet string "givenName")
                    31 0a  -- Begin the attribute value set
                        04 08 4a 6f 6e 61 74 68 61 6e -- The attribute value
                                                      -- (octet string "Jonathan")
            30 19 -- Begin the sequence for the third modification
                0a 01 02 -- The replace modification type (enumerated value 2)
                30 14 -- Begin the attribute sequence
                    04 02 63 6e -- The attribute description (octet string "cn")
                    31 0e -- Begin the attribute value set
                        04 0c 4a 6f 6e 61 74 68 61 6e -- The attribute value
                        20 44 6f 65                   -- (octet string "Jonathan Doe")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        change1 = LDAPModify_change(
            operation=ModifyOperations.delete,
            modification=LDAPPartialAttribute(type_="givenName", values=[b"John"]))
        change2 = LDAPModify_change(
            operation=ModifyOperations.add,
            modification=LDAPPartialAttribute(type_="givenName", values=[b"Jonathan"]))
        change3 = LDAPModify_change(
            operation=ModifyOperations.replace,
            modification=LDAPPartialAttribute(type_="cn", values=[b"Jonathan Doe"]))
        operation = LDAPModifyRequest(object_="uid=jdoe,ou=People,dc=example,dc=com",
                                      changes=[change1, change2, change3])
        expectation = LDAPMessage(msg_id=2, operation=operation)
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPModifyResponse(self):
        case = """
30 0c -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    67 07 -- Begin the modify response protocol op
        0a 01 00 -- success result code (enumerated value 0)
        04 00 -- No matched DN (0-byte octet string)
        04 00 -- No diagnostic message (0-byte octet string)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPModifyResponse(
            resultCode=ResultCodes.success, matchedDN="", diagnosticMessage=""))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPModifyDNRequest_rename(self):
        case = """
30 3c -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    6c 37 -- Begin the modify DN request protocol op
        04 24 75 69 64 3d 6a 64 6f 65 -- The DN of the entry to rename (octet string
            2c 6f 75 3d 50 65 6f 70   -- "uid=jdoe,ou=People,dc=example,dc=com")
            6c 65 2c 64 63 3d 65 78
            61 6d 70 6c 65 2c 64 63
            3d 63 6f 6d
        04 0c 75 69 64 3d 6a 6f 68 6e -- The new RDN (octet string "uid=john.doe")
            2e 64 6f 65
        01 01 ff -- Delete the old RDN value (boolean true)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPModifyDNRequest(
            entry="uid=jdoe,ou=People,dc=example,dc=com", newrdn="uid=john.doe", deleteoldrdn=True))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPModifyDNRequest_move(self):
        case = """
30 5c -- Begin the LDAPMessage sequence
    02 01 03 -- The message ID (integer value 3)
    6c 57 -- Begin the modify DN request protocol op
        04 28 75 69 64 3d 6a 6f 68 6e -- The DN of the entry to move (octet string
            2e 64 6f 65 2c 6f 75 3d   -- "uid=john.doe,ou=People,dc=example,dc=com")
            50 65 6f 70 6c 65 2c 64
            63 3d 65 78 61 6d 70 6c
            65 2c 64 63 3d 63 6f 6d
        04 0c 75 69 64 3d 6a 6f 68 6e -- The new RDN (octet string "uid=john.doe")
            2e 64 6f 65
        01 01 00 -- Don’t delete the old RDN value (boolean false)
        80 1a 6f 75 3d 55 73 65 72 73 -- The new superior DN (octet string
            2c 64 63 3d 65 78 61 6d   -- "ou=Users,dc=example,dc=com" with type
            70 6c 65 2c 64 63 3d 63   -- context-specific primitive zero)
            6f 6d
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=3, operation=LDAPModifyDNRequest(
            entry="uid=john.doe,ou=People,dc=example,dc=com", newrdn="uid=john.doe",
            deleteoldrdn=False, newSuperior="ou=Users,dc=example,dc=com"))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPModifyDNRequest_combined(self):
        case = """
30 58 -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    6c 53 -- Begin the modify DN request protocol op
        04 24 75 69 64 3d 6a 64 6f 65 -- The DN of the entry to move/rename (octet
            2c 6f 75 3d 50 65 6f 70   -- string "uid=jdoe,ou=People,dc=example,dc=com")
            6c 65 2c 64 63 3d 65 78
            61 6d 70 6c 65 2c 64 63
            3d 63 6f 6d
        04 0c 75 69 64 3d 6a 6f 68 6e -- The new RDN (octet string "uid=john.doe")
            2e 64 6f 65
        01 01 ff -- Delete the old RDN value (boolean true)
        80 1a 6f 75 3d 55 73 65 72 73 -- The new superior DN (octet string
            2c 64 63 3d 65 78 61 6d   -- "ou=Users,dc=example,dc=com" with type
            70 6c 65 2c 64 63 3d 63   -- context-specific primitive zero)
            6f 6d
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPModifyDNRequest(
            entry="uid=jdoe,ou=People,dc=example,dc=com", newrdn="uid=john.doe",
            deleteoldrdn=True, newSuperior="ou=Users,dc=example,dc=com"))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPModifyDNResponse(self):
        case = """
30 0c -- Begin the LDAPMessage sequence
    02 01 02 -- The message ID (integer value 2)
    6d 07 -- Begin the modify DN response protocol op
        0a 01 00 -- success result code (enumerated value 0)
        04 00 -- No matched DN (0-byte octet string)
        04 00 -- No diagnostic message (0-byte octet string)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=2, operation=LDAPModifyDNResponse(
            resultCode=ResultCodes.success, matchedDN="", diagnosticMessage=""))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_present(self):
        case = """
87 03 75 69 64 -- The octet string "uid" with type context-specific primitive seven
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_present.tag)
        result = LDAPFilter_present.from_wire(content)

        expectation = LDAPFilter_present("uid")
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_equalityMatch(self):
        case = """
a3 0b -- Begin the AttributeValueAssertion sequence with type
      -- context-specific constructed three
    04 03 75 69 64 -- The attribute description (octet string "uid")
    04 04 6a 64 6f 65 -- The assertion value (octet string "jdoe")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_equalityMatch.tag)
        result = LDAPFilter_equalityMatch.from_wire(content)

        expectation = LDAPFilter_equalityMatch(attributeDesc="uid", assertionValue=b"jdoe")
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_greaterOrEqual(self):
        case = """
a5 26 -- Begin the AttributeValueAssertion sequence with type
      -- context-specific constructed five
    04 0f 63 72 65 61 74 65 54 69 -- The attribute description
        6d 65 73 74 61 6d 70      -- (octet string "createTimestamp")
    04 13 32 30 31 37 30 31 30 32 -- The assertion value
        30 33 30 34 30 35 2e 36   -- (octet string "20170102030405.678Z")
        37 38 5a
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_greaterOrEqual.tag)
        result = LDAPFilter_greaterOrEqual.from_wire(content)

        expectation = LDAPFilter_greaterOrEqual(
            attributeDesc="createTimestamp", assertionValue=b"20170102030405.678Z")
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_lessOrEqual(self):
        case = """
a6 16 -- Begin the AttributeValueAssertion sequence with type
      -- context-specific constructed six
    04 0e 61 63 63 6f 75 6e 74 42 -- The attribute description
        61 6c 61 6e 63 65         -- (octet string "accountBalance")
    04 04 31 32 33 34             -- The assertion value (octet string "1234")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_lessOrEqual.tag)
        result = LDAPFilter_lessOrEqual.from_wire(content)

        expectation = LDAPFilter_lessOrEqual(
            attributeDesc="accountBalance", assertionValue=b"1234")
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_approximateMatch(self):
        case = """
a8 11 -- Begin the AttributeValueAssertion sequence with type
      -- context-specific constructed eight
    04 09 67 69 76 65 6e 4e 61 6d -- The attribute description
        65                        -- (octet string "givenName")
    04 04 4a 6f 68 6e             -- The assertion value (octet string "John")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_approxMatch.tag)
        result = LDAPFilter_approxMatch.from_wire(content)

        expectation = LDAPFilter_approxMatch(
            attributeDesc="givenName", assertionValue=b"John")
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_substring(self):
        case = """
a4 1f -- Begin the SubstringFilter sequence with type
      -- context-specific constructed four
    04 02 63 6e -- The attribute description (octet string "cn")
    30 19 -- Begin the substrings sequence
        80 03 61 62 63 -- The initial element (octet string "abc") with type
                       -- context-specific primitive zero
        81 03 64 65 66 -- The first any element (octet string "def") with type
                       -- context-specific primitive one
        81 03 6c 6d 6e -- The second any element (octet string "lmn") with type
                       -- context-specific primitive one
        81 03 75 76 77 -- The third any element (octet string "uvw") with type
                       -- context-specific primitive one
        82 03 78 79 7a -- The final element (octet string "xyz") with type
                       -- context-specific primitive two
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_substrings.tag)
        result = LDAPFilter_substrings.from_wire(content)

        sub1 = LDAPFilter_substrings_initial(b"abc")
        sub2 = LDAPFilter_substrings_any(b"def")
        sub3 = LDAPFilter_substrings_any(b"lmn")
        sub4 = LDAPFilter_substrings_any(b"uvw")
        sub5 = LDAPFilter_substrings_final(b"xyz")
        expectation = LDAPFilter_substrings(
            type_="cn", substrings=[sub1, sub2, sub3, sub4, sub5])
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_extensibleMatch_1(self):
        case = """
a9 0b -- Begin the MatchingRuleAssertion sequence with type
      -- context-specific constructed nine
    82 03 75 69 64 -- The attribute description (octet string "uid" with type
                   -- context-specific primitive two)
    83 04 6a 64 6f 65 -- The assertion value (octet string "jdoe" with type
                      -- context-specific primitive three
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_extensibleMatch.tag)
        result = LDAPFilter_extensibleMatch.from_wire(content)

        expectation = LDAPFilter_extensibleMatch(type_="uid", matchValue=b"jdoe")
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_extensibleMatch_2(self):
        case = """
a9 16 -- Begin the MatchingRuleAssertion sequence with type
      -- context-specific constructed nine
    81 0f 63 61 73 65 49 67 6e 6f -- The matching rule ID (octet string
    72 65 4d 61 74 63 68          -- "caseIgnoreMatch" with type
                                  -- context-specific primitive one)
    83 03 66 6f 6f -- The assertion value (octet string "foo" with type
                   -- context-specific primitive three
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_extensibleMatch.tag)
        result = LDAPFilter_extensibleMatch.from_wire(content)

        expectation = LDAPFilter_extensibleMatch(
            matchingRule="caseIgnoreMatch", matchValue=b"foo")
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_extensibleMatch_3(self):
        case = """
a9 1f -- Begin the MatchingRuleAssertion sequence with type
      -- context-specific constructed nine
    81 0f 63 61 73 65 49 67 6e 6f -- The matching rule ID (octet string
    72 65 4d 61 74 63 68          -- "caseIgnoreMatch" with type
    82 03 75 69 64 -- The attribute description (octet string "uid" with type
                   -- context-specific primitive two)
    83 04 6a 64 6f 65 -- The assertion value (octet string "jdoe" with type
                      -- context-specific primitive three
    84 01 ff -- The dnAttributes flag (boolean true)
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_extensibleMatch.tag)
        result = LDAPFilter_extensibleMatch.from_wire(content)

        expectation = LDAPFilter_extensibleMatch(
            matchingRule="caseIgnoreMatch", type_="uid", matchValue=b"jdoe", dnAttributes=True)
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_and(self):
        case = """
a0 1e -- Begin the and set with type context-specific constructed zero
    a3 11 -- Begin the AttributeValueAssertion sequence with type
          -- context-specific constructed three
        04 09 67 69 76 65 6e 4e 61 6d -- The attribute description
        65                            -- (octet string "givenName")
        04 04 4a 6f 68 6e -- The assertion value (octet string "John")
    a3 09 -- Begin the AttributeValueAssertion sequence with type
          -- context-specific constructed three
        04 02 73 6e -- The attribute description (octet string "sn")
        04 03 44 6f 65 -- The assertion value (octet string "Doe")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_and.tag)
        result = LDAPFilter_and.from_wire(content)

        filter1 = LDAPFilter_equalityMatch(attributeDesc="givenName", assertionValue=b"John")
        filter2 = LDAPFilter_equalityMatch(attributeDesc="sn", assertionValue=b"Doe")
        expectation = LDAPFilter_and(filters=[filter1, filter2])
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_true(self):
        case = """
a0 00 -- An empty and set with type context-specific constructed zero
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_and.tag)
        result = LDAPFilter_and.from_wire(content)

        expectation = LDAPFilter_and(filters=[])
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_or(self):
        case = """
a1 2a -- Begin the or set with type context-specific constructed one
    a3 11 -- Begin the AttributeValueAssertion sequence with type
          -- context-specific constructed three
        04 09 67 69 76 65 6e 4e 61 6d -- The attribute description
        65                            -- (octet string "givenName")
        04 04 4a 6f 68 6e -- The assertion value (octet string "John")
    a3 15 -- Begin the AttributeValueAssertion sequence with type
          -- context-specific constructed three
        04 09 67 69 76 65 6e 4e 61 6d -- The attribute description
        65                            -- (octet string "givenName")
        04 08 4a 6f 6e 61 74 68 61 6e -- The assertion value (octet string "Jonathan")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_or.tag)
        result = LDAPFilter_or.from_wire(content)

        filter1 = LDAPFilter_equalityMatch(attributeDesc="givenName", assertionValue=b"John")
        filter2 = LDAPFilter_equalityMatch(attributeDesc="givenName", assertionValue=b"Jonathan")
        expectation = LDAPFilter_or(filters=[filter1, filter2])
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_false(self):
        case = """
a1 00 -- An empty and set with type context-specific constructed zero
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_or.tag)
        result = LDAPFilter_or.from_wire(content)

        expectation = LDAPFilter_or(filters=[])
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    def test_LDAPFilter_not(self):
        case = """
a2 13 -- Begin the not filter with type context-specific constructed two
    a3 11 -- Begin the AttributeValueAssertion sequence with type
          -- context-specific constructed three
        04 09 67 69 76 65 6e 4e 61 6d -- The attribute description
        65                            -- (octet string "givenName")
        04 04 4a 6f 68 6e -- The assertion value (octet string "John")
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPFilter_not.tag)
        result = LDAPFilter_not.from_wire(content)

        expectation = LDAPFilter_not(value=LDAPFilter_equalityMatch(
            attributeDesc="givenName", assertionValue=b"John"))
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    # TODO LDAPSearch

    def test_LDAPUnbindRequest(self):
        case = """
30 05 -- Begin the LDAPMessage sequence
    02 01 03 -- The message ID (integer value 3)
    42 00 -- The unbind request protocol op
"""
        content = self.first_level_unwrap(unhexlify(case), LDAPMessage.tag)
        result = LDAPMessage.from_wire(content)

        expectation = LDAPMessage(msg_id=3, operation=LDAPUnbindRequest())
        self.assertEqual(expectation, result)
        self.assertEqual(unhexlify(case), result.to_wire())

    # TODO LDAPIntermediateResponse
