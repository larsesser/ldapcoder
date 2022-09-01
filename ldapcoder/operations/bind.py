"""LDAP protocol message conversion; no application logic here."""

import abc
from typing import List, Optional

from ldapcoder.berutils import (
    BERBase, BERInteger, BEROctetString, BERSequence, TagClasses,
)
from ldapcoder.exceptions import DuplicateTagReceivedError, UnknownTagError
from ldapcoder.ldaputils import (
    LDAPDN, DistinguishedName, LDAPProtocolRequest, LDAPString, decode,
)
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
        if len(vals) < 1:
            cls.handle_missing_vals(vals)
        if len(vals) > 2:
            cls.handle_additional_vals(vals[2:])

        mechanism = decode(vals[0], LDAPString).string
        # per https://ldap.com/ldapv3-wire-protocol-reference-bind/
        # Credentials are optional and not always provided
        credentials = None
        if len(vals) >= 2:
            credentials = decode(vals[1], BEROctetString).bytes_
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
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPBindRequest(LDAPProtocolRequest, BERSequence):
    """Authentication attempt of the client to the server.

    Note that the authentication process may be multi-stage processes, which include
    multiple BindRequests and BindResponses to be sent to be complete.
    """
    _tag_class = TagClasses.APPLICATION
    _tag = 0x00
    version: int
    name: DistinguishedName
    auth: LDAPAuthenticationChoice

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindRequest":
        vals = cls.unwrap(content)
        if len(vals) < 3:
            cls.handle_missing_vals(vals)
        if len(vals) > 3:
            cls.handle_additional_vals(vals[3:])

        version = decode(vals[0], BERInteger).integer
        name = decode(vals[1], LDAPDN).dn

        auth_tag, auth_content = vals[2]
        if auth_tag not in AUTHENTICATION_CHOICES:
            raise UnknownTagError(auth_tag)
        auth = AUTHENTICATION_CHOICES[auth_tag].from_wire(auth_content)

        r = cls(version=version, name=name, auth=auth)
        return r

    def __init__(self, version: int, name: DistinguishedName, auth: LDAPAuthenticationChoice):
        self.version = version
        self.name = name
        self.auth = auth

    def to_wire(self) -> bytes:
        return self.wrap([BERInteger(self.version), LDAPDN(self.name), self.auth])

    def __repr__(self) -> str:
        attributes = [f"version={self.version}", f"dn={self.name}", f"auth={self.auth!r}"]
        return self.__class__.__name__ + "(" + ", ".join(attributes) + ")"


class LDAPBindResponse_serverSaslCreds(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x07


# BindResponse ::= [APPLICATION 1] SEQUENCE {
#      COMPONENTS OF LDAPResult,
#      serverSaslCreds    [7] OCTET STRING OPTIONAL }
# [RFC4511]
@PROTOCOL_OPERATIONS.add
class LDAPBindResponse(LDAPResult):
    """Respond to a clients authentication Request.

    Note that the authentication process may be multi-stage processes, which include
    multiple BindRequests and BindResponses to be sent to be complete.
    """
    _tag_class = TagClasses.APPLICATION
    _tag = 0x01
    serverSaslCreds: Optional[bytes]

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindResponse":
        vals = cls.unwrap(content)
        if len(vals) < 3:
            cls.handle_missing_vals(vals)

        resultCode = decode(vals[0], LDAPResultCode).member
        matchedDN = decode(vals[1], LDAPDN).dn
        diagnosticMessage = decode(vals[2], LDAPString).string

        referral = None
        serverSaslCreds = None
        additional = []
        for unknown_tag, unknown_content in vals[3:]:
            if unknown_tag == LDAPReferral.tag:
                if referral is not None:
                    raise DuplicateTagReceivedError("referral")
                referral = LDAPReferral.from_wire(unknown_content).uris
            elif unknown_tag == LDAPBindResponse_serverSaslCreds.tag:
                if serverSaslCreds is not None:
                    raise DuplicateTagReceivedError("serverSaslCreds")
                serverSaslCreds = LDAPBindResponse_serverSaslCreds.from_wire(unknown_content).bytes_
            else:
                additional.append((unknown_tag, unknown_content))
        if additional:
            cls.handle_additional_vals(additional)

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
        matchedDN: DistinguishedName,
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
