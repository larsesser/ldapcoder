"""LDAP protocol message conversion; no application logic here."""

import enum
from typing import List, Optional, Type

from ldapcoder.berutils import BERBase, BEREnumerated, BERSequence, TagClasses
from ldapcoder.exceptions import HandlingError
from ldapcoder.ldaputils import (
    LDAPDN, LDAPURI, DistinguishedName, LDAPProtocolResponse, LDAPString, decode,
)


# Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
class LDAPReferral(BERSequence):
    """Referrals are basically links to other servers.

    They are send if the contacted server cannot or will not perform the requested
    operation, but knows that one or more other servers may be able to do so.
    """
    _tag_class = TagClasses.CONTEXT
    _tag = 0x03
    uris: List[str]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPReferral":
        vals = cls.unwrap(content)
        uris = [decode(val, LDAPURI).string for val in vals]
        return cls(uris=uris)

    def __init__(self, uris: List[str]):
        if len(uris) == 0:
            raise ValueError(f"{self.__class__.__name__} expects at least one uri.")
        self.uris = uris

    def to_wire(self) -> bytes:
        return self.wrap([LDAPURI(uri) for uri in self.uris])

    def __repr__(self) -> str:
        return self.__class__.__name__ + f"(value={self.uris}"


@enum.unique
class ResultCodes(enum.IntEnum):
    """All LDAPResultCodes as defined in [RFC4511]."""
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

    def to_exception(self, matchedDN: DistinguishedName = None, diagnosticMessage: str = None,
                     referral: Optional[List[str]] = None) -> HandlingError:
        matchedDN = matchedDN or DistinguishedName("")
        diagnosticMessage = diagnosticMessage or ""
        result = LDAPResult(resultCode=self, matchedDN=matchedDN,
                            diagnosticMessage=diagnosticMessage, referral=referral)
        return HandlingError(result=result)


class LDAPResultCode(BEREnumerated):
    member: ResultCodes

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
# [RFC4511]
class LDAPResult(LDAPProtocolResponse, BERSequence):
    """Return success or failure indications to the client.

    If more than one resultCode is suitable, the server will decide for one. Servers
    may return substituted result codes to prevent unauthorized disclosures.

    The diagnosticMessage field may be used to send additional free-text information
    about the resultCode to the client. This is intended to be in humanreadable format.
    """
    resultCode: ResultCodes
    matchedDN: DistinguishedName
    diagnosticMessage: str
    referral: Optional[List[str]]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPResult":
        vals = cls.unwrap(content)
        if len(vals) < 3:
            cls.handle_missing_vals(vals)
        if len(vals) > 4:
            cls.handle_additional_vals(vals[4:])

        resultCode = decode(vals[0], LDAPResultCode).member
        matchedDN = decode(vals[1], LDAPDN).dn
        diagnosticMessage = decode(vals[2], LDAPString).string

        referral = None
        if len(vals) >= 4:
            referral = decode(vals[3], LDAPReferral).uris

        r = cls(
            resultCode=resultCode,
            matchedDN=matchedDN,
            diagnosticMessage=diagnosticMessage,
            referral=referral,
        )
        return r

    def __init__(self, resultCode: ResultCodes, matchedDN: DistinguishedName, diagnosticMessage: str,
                 referral: List[str] = None):
        # the referral result code is set iff there are referrals
        if (resultCode is resultCode.referral and referral is None
                or resultCode is not resultCode.referral and referral is not None):
            raise ValueError("resultCode is ResultCode.referral iff referral is given.")
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

    @property
    def exception(self) -> HandlingError:
        return HandlingError(result=self)
