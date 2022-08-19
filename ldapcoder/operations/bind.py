"""LDAP protocol message conversion; no application logic here."""

import abc
from typing import List, Optional

from ldapcoder.berutils import (
    BERBase, BERInteger, BEROctetString, BERSequence, TagClasses,
)
from ldapcoder.exceptions import UnknownTagError
from ldapcoder.ldaputils import LDAPDN, LDAPProtocolRequest, LDAPString, check, decode
from ldapcoder.registry import AUTHENTICATION_CHOICES, PROTOCOL_OPERATIONS
from ldapcoder.result import LDAPReferral, LDAPResult, LDAPResultCode, ResultCodes


# AuthenticationChoice ::= CHOICE {
#      simple                  [0] OCTET STRING,
#                -- 1 and 2 reserved
#      sasl                    [3] SaslCredentials,
#      ...  }
class LDAPAuthenticationChoice(BERBase, metaclass=abc.ABCMeta):
    _tag_class = TagClasses.CONTEXT


@AUTHENTICATION_CHOICES.add
class LDAPBindRequest_SimpleAuthentication(LDAPAuthenticationChoice, BEROctetString):
    _tag = 0x00


# SaslCredentials ::= SEQUENCE {
#      mechanism               LDAPString,
#      credentials             OCTET STRING OPTIONAL }
@AUTHENTICATION_CHOICES.add
class LDAPBindRequest_SaslAuthentication(LDAPAuthenticationChoice, BERSequence):
    _tag = 0x03
    mechanism: str
    credentials: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindRequest_SaslAuthentication":
        vals = cls.unwrap(content)
        check(len(vals) in {1, 2})

        mechanism = decode(vals[0], LDAPString).value
        # per https://ldap.com/ldapv3-wire-protocol-reference-bind/
        # Credentials are optional and not always provided
        if len(vals) == 1:
            return cls(mechanism=mechanism, credentials=None)

        credentials = decode(vals[1], BEROctetString).value
        return cls(mechanism=mechanism, credentials=credentials)

    def __init__(self, mechanism: str, credentials: bytes = None):
        self.mechanism = mechanism
        self.credentials = credentials

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPString(self.mechanism)]
        if self.credentials:
            ret.append(BEROctetString(self.credentials))
        return self.wrap(ret)

    def __repr__(self) -> str:
        attributes = [f"mechanism={self.mechanism}"]
        if self.credentials:
            attributes.append(f"credentials={self.credentials!r}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


# BindRequest ::= [APPLICATION 0] SEQUENCE {
#      version                 INTEGER (1 ..  127),
#      name                    LDAPDN,
#      authentication          AuthenticationChoice }
@PROTOCOL_OPERATIONS.add
class LDAPBindRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x00
    version: int
    dn: str
    auth: LDAPAuthenticationChoice

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindRequest":
        vals = cls.unwrap(content)
        check(len(vals) == 3)

        version = decode(vals[0], BERInteger).value
        dn = decode(vals[1], LDAPDN).value

        auth_tag, auth_content = vals[2]
        if auth_tag not in AUTHENTICATION_CHOICES:
            raise UnknownTagError(auth_tag)
        auth = AUTHENTICATION_CHOICES[auth_tag].from_wire(auth_content)
        assert isinstance(auth, LDAPAuthenticationChoice)

        r = cls(version=version, dn=dn, auth=auth)
        return r

    def __init__(self, version: int, dn: str, auth: LDAPAuthenticationChoice):
        self.version = version
        self.dn = dn
        self.auth = auth

    def to_wire(self) -> bytes:
        return self.wrap([BERInteger(self.version), LDAPDN(self.dn), self.auth])

    def __repr__(self) -> str:
        attributes = [f"version={self.version}", f"dn={self.dn}", f"auth={self.auth!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


class LDAPBindResponse_serverSaslCreds(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x07


# BindResponse ::= [APPLICATION 1] SEQUENCE {
#      COMPONENTS OF LDAPResult,
#      serverSaslCreds    [7] OCTET STRING OPTIONAL }
@PROTOCOL_OPERATIONS.add
class LDAPBindResponse(LDAPResult):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x01
    serverSaslCreds: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindResponse":
        vals = cls.unwrap(content)
        check(3 <= len(vals) <= 5)

        resultCode = decode(vals[0], LDAPResultCode).value
        matchedDN = decode(vals[1], LDAPDN).value
        diagnosticMessage = decode(vals[2], LDAPString).value

        referral = None
        serverSaslCreds = None
        if len(vals) == 4:
            unknown_tag, unknown_content = vals[3]
            if unknown_tag == LDAPReferral.tag:
                referral = decode(vals[3], LDAPReferral).value
            elif unknown_tag == LDAPBindResponse_serverSaslCreds.tag:
                serverSaslCreds = decode(vals[3], LDAPBindResponse_serverSaslCreds).value
            else:
                raise UnknownTagError(unknown_tag)
        elif len(vals) == 5:
            referral = decode(vals[3], LDAPReferral).value
            serverSaslCreds = decode(vals[4], LDAPBindResponse_serverSaslCreds).value

        r = cls(
            resultCode=resultCode,
            matchedDN=matchedDN,
            diagnosticMessage=diagnosticMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
        )
        return r

    def __init__(
        self,
        resultCode: ResultCodes,
        matchedDN: str,
        diagnosticMessage: str,
        referral: List[str] = None,
        serverSaslCreds: bytes = None,
    ):
        super().__init__(resultCode, matchedDN, diagnosticMessage, referral)
        self.serverSaslCreds = serverSaslCreds

    def to_wire(self) -> bytes:
        ret: List[BERBase] = [LDAPResultCode(self.resultCode), LDAPDN(self.matchedDN),
                              LDAPString(self.diagnosticMessage)]
        if self.referral is not None:
            ret.append(LDAPReferral(self.referral))
        if self.serverSaslCreds is not None:
            ret.append(LDAPBindResponse_serverSaslCreds(self.serverSaslCreds))
        return self.wrap(ret)

    def __repr__(self) -> str:
        attributes = [f"resultCode={self.resultCode!r}", f"matchedDN={self.matchedDN}",
                      f"diagnosticMessage={self.diagnosticMessage}"]
        if self.referral:
            attributes.append(f"referral={self.referral}")
        if self.serverSaslCreds:
            attributes.append(f"serverSaslCred={self.serverSaslCreds!r}")
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"
