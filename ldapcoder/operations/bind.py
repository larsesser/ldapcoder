"""LDAP protocol message conversion; no application logic here."""

import abc
import enum
import string
from typing import Optional, List, Mapping, Type, Union, Tuple, TypeVar

from ldapcoder.ldaputils import (
    alloc_ldap_message_id, escape, check, decode, LDAPString, LDAPDN, LDAPRelativeDN,
    LDAPURI, LDAPMessageId, LDAPProtocolOp, LDAPProtocolRequest, LDAPProtocolResponse,
    LDAPException, LDAPAttributeDescription, LDAPAssertionValue, LDAPAttributeValueAssertion,
    LDAPAttributeSelection, LDAPPartialAttribute, LDAPPartialAttributeList,
    LDAPAttribute, LDAPAttributeList, LDAPOID)
from ldapcoder.result import LDAPReferral, ResultCodes, LDAPResultCode, LDAPResult

from ldaptor.protocols.pureber import (
    BERBoolean,
    BEREnumerated,
    BERInteger,
    BERNull,
    BEROctetString,
    BERSequence,
    BERSet,
    int2berlen,
    UnknownBERTag,
    BERBase,
    TagClasses,
    ber_unwrap,
)


# AuthenticationChoice ::= CHOICE {
#      simple                  [0] OCTET STRING,
#                -- 1 and 2 reserved
#      sasl                    [3] SaslCredentials,
#      ...  }
class LDAPBindRequest_SimpleAuthentication(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x00


# SaslCredentials ::= SEQUENCE {
#      mechanism               LDAPString,
#      credentials             OCTET STRING OPTIONAL }
class LDAPBindRequest_SaslAuthentication(BERSequence):
    _tag_class = TagClasses.CONTEXT
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


# BindRequest ::= [APPLICATION 0] SEQUENCE {
#      version                 INTEGER (1 ..  127),
#      name                    LDAPDN,
#      authentication          AuthenticationChoice }
class LDAPBindRequest(LDAPProtocolRequest, BERSequence):
    _tag_class = TagClasses.APPLICATION
    _tag = 0x00
    version: int
    dn: str
    auth: Union[bytes, Tuple[str, Optional[bytes]]]
    sasl: bool

    @classmethod
    def from_wire(cls, content: bytes) -> "LDAPBindRequest":
        vals = cls.unwrap(content)
        check(len(vals) == 3)

        version = decode(vals[0], BERInteger).value
        dn = decode(vals[1], LDAPDN).value

        auth_tag, auth_content = vals[2]
        auth: Union[bytes, Tuple[str, Optional[bytes]]]
        if auth_tag == LDAPBindRequest_SimpleAuthentication.tag:
            auth = LDAPBindRequest_SimpleAuthentication.from_wire(auth_content).value
        elif auth_tag == LDAPBindRequest_SaslAuthentication.tag:
            auth_ = LDAPBindRequest_SaslAuthentication.from_wire(auth_content)
            auth = (auth_.mechanism, auth_.credentials)
        else:
            raise ValueError

        r = cls(version=version, dn=dn, auth=auth)
        return r

    def __init__(self, version: int, dn: str,
                 auth: Union[bytes, Tuple[str, Optional[bytes]]]):
        """Constructor for LDAP Bind Request

        For sasl=False, pass a string password for 'auth'
        For sasl=True, pass a tuple of (mechanism, credentials) for 'auth'"""
        self.version = version
        self.dn = dn
        self.auth = auth
        if isinstance(auth, bytes):
            sasl = False
        elif isinstance(auth, tuple):
            sasl = True
        else:
            raise ValueError
        self.sasl = sasl

    def to_wire(self) -> bytes:
        auth: Union[LDAPBindRequest_SaslAuthentication, LDAPBindRequest_SimpleAuthentication]
        if self.sasl:
            assert isinstance(self.auth, tuple)
            # since the credentails for SASL is optional must check first
            # if credentials are None don't send them.
            mechanism = self.auth[0]
            credentials = self.auth[1] if len(self.auth) > 1 else None
            auth = LDAPBindRequest_SaslAuthentication(
                mechanism=mechanism, credentials=credentials)
        else:
            assert isinstance(self.auth, bytes)
            auth = LDAPBindRequest_SimpleAuthentication(self.auth)
        return self.wrap([BERInteger(self.version), LDAPDN(self.dn), auth])

    def __repr__(self):
        auth = "*" * len(self.auth)
        l = []
        l.append("version=%d" % self.version)
        l.append("dn=%s" % repr(self.dn))
        l.append("auth=%s" % repr(auth))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        l.append("sasl=%s" % repr(self.sasl))
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBindResponse_serverSaslCreds(BEROctetString):
    _tag_class = TagClasses.CONTEXT
    _tag = 0x07

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % self.value
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                self.value,
                self.tag,
            )


# BindResponse ::= [APPLICATION 1] SEQUENCE {
#      COMPONENTS OF LDAPResult,
#      serverSaslCreds    [7] OCTET STRING OPTIONAL }
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
                raise UnknownBERTag(unknown_tag)
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

    def __repr__(self):
        return LDAPResult.__repr__(self)
