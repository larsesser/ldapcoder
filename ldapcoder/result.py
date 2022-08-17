"""LDAP protocol message conversion; no application logic here."""

import enum
from typing import List, Optional, Type

from ldapcoder.berutils import BERBase, BEREnumerated, BERSequence, TagClasses
from ldapcoder.ldaputils import (
    LDAPDN, LDAPURI, LDAPException, LDAPProtocolResponse, LDAPString, check, decode,
)


# Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
class LDAPReferral(BERSequence):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x03
    value: List[str]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPReferral":
        vals = cls.unwrap(content)
        uris = [decode(val, LDAPURI).value for val in vals]
        return cls(uris=uris)

    def __init__(self, uris: List[str]):
        check(len(uris) >= 1)
        self.value = uris

    def to_wire(self) -> bytes:
        return self.wrap([LDAPURI(uri) for uri in self.value])

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.value}"


@enum.unique
class ResultCodes(enum.IntEnum):
    success = 0
    operationsError = 1
    protocolError = 2
    timeLimitExceeded = 3
    sizeLimitExceeded = 4
    compareFalse = 5
    compareTrue = 6
    authMethodNotSupported = 7
    strongerAuthRequired = 8
    # 9 reserved
    referral = 10
    adminLimitExceeded = 11
    unavailableCriticalExtension = 12
    confidentialityRequired = 13
    saslBindInProgress = 14
    noSuchAttribute = 16
    undefinedAttributeType = 17
    inappropriateMatching = 18
    constraintViolation = 19
    attributeOrValueExists = 20
    invalidAttributeSyntax = 21
    # 22-31 unused
    noSuchObject = 32
    aliasProblem = 33
    invalidDNSyntax = 34
    # 35 reserved for undefined isLeaf
    aliasDereferencingProblem = 36
    # 37-47 unused
    inappropriateAuthentication = 48
    invalidCredentials = 49
    insufficientAccessRights = 50
    busy = 51
    unavailable = 52
    unwillingToPerform = 53
    loopDetect = 54
    # 55-63 unused
    namingViolation = 64
    objectClassViolation = 65
    notAllowedOnNonLeaf = 66
    notAllowedOnRDN = 67
    entryAlreadyExists = 68
    objectClassModsProhibited = 69
    # 70 reserved for CLDAP
    affectsMultipleDSAs = 71
    # 72-79 unused
    other = 80
    # ...

    @property
    def bytes_name(self) -> bytes:
        return self.name.encode("utf-8")

    def to_exception(self, message: bytes = None) -> LDAPException:
        return LDAPException(resultCode=self, message=message)


class LDAPResultCode(BEREnumerated):
    value: ResultCodes

    @classmethod
    def enum_cls(cls) -> Type[enum.IntEnum]:
        return ResultCodes


# LDAPResult ::= SEQUENCE {
#      resultCode         ENUMERATED {
#           success                      (0),
#           operationsError              (1),
#           protocolError                (2),
#           timeLimitExceeded            (3),
#           sizeLimitExceeded            (4),
#           compareFalse                 (5),
#           compareTrue                  (6),
#           authMethodNotSupported       (7),
#           strongerAuthRequired         (8),
#  -- 9 reserved --
#           referral                     (10),
#           adminLimitExceeded           (11),
#           unavailableCriticalExtension (12),
#           confidentialityRequired      (13),
#           saslBindInProgress           (14),
#           noSuchAttribute              (16),
#           undefinedAttributeType       (17),
#           inappropriateMatching        (18),
#           constraintViolation          (19),
#           attributeOrValueExists       (20),
#           invalidAttributeSyntax       (21),
#  -- 22-31 unused --
#           noSuchObject                 (32),
#           aliasProblem                 (33),
#           invalidDNSyntax              (34),
#  -- 35 reserved for undefined isLeaf --
#           aliasDereferencingProblem    (36),
#  -- 37-47 unused --
#           inappropriateAuthentication  (48),
#           invalidCredentials           (49),
#           insufficientAccessRights     (50),
#           busy                         (51),
#           unavailable                  (52),
#           unwillingToPerform           (53),
#           loopDetect                   (54),
#  -- 55-63 unused --
#           namingViolation              (64),
#           objectClassViolation         (65),
#           notAllowedOnNonLeaf          (66),
#           notAllowedOnRDN              (67),
#           entryAlreadyExists           (68),
#           objectClassModsProhibited    (69),
#  -- 70 reserved for CLDAP --
#           affectsMultipleDSAs          (71),
#  -- 72-79 unused --
#           other                        (80),
#           ...  },
#      matchedDN          LDAPDN,
#      diagnosticMessage  LDAPString,
#      referral           [3] Referral OPTIONAL }
class LDAPResult(LDAPProtocolResponse, BERSequence):
    resultCode: ResultCodes
    matchedDN: str
    diagnosticMessage: str
    referral: Optional[List[str]]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPResult":
        vals = cls.unwrap(content)
        check(3 <= len(vals) <= 4)

        resultCode = decode(vals[0], LDAPResultCode).value
        matchedDN = decode(vals[1], LDAPDN).value
        diagnosticMessage = decode(vals[2], LDAPString).value

        referral = None
        if len(vals) == 4:
            referral = decode(vals[3], LDAPReferral).value

        r = cls(
            resultCode=resultCode,
            matchedDN=matchedDN,
            diagnosticMessage=diagnosticMessage,
            referral=referral,
        )
        return r

    def __init__(self, resultCode: ResultCodes, matchedDN: str, diagnosticMessage: str,
                 referral: List[str] = None):
        self.resultCode = resultCode
        self.matchedDN = matchedDN
        self.diagnosticMessage = diagnosticMessage
        self.referral = referral

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPResultCode(self.resultCode), LDAPDN(self.matchedDN),
                              LDAPString(self.diagnosticMessage)]
        if self.referral is not None:
            ret.append(LDAPReferral(self.referral))
        return self.wrap(ret)

    def __repr__(self) -> str:
        attributes = [f"resultCode={self.resultCode!r}", f"matchedDN={self.matchedDN}",
                      f"diagnosticMessage={self.diagnosticMessage}"]
        if self.referral:
            attributes.append(f"referral={self.referral}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"
