from typing import Any

from ldapcoder.ldaputils import DistinguishedName
from ldapcoder.message import LDAPMessage
from ldapcoder.operations.extended import LDAPExtendedResponse
from ldapcoder.registry import EXTENDED_RESPONSES
from ldapcoder.result import ResultCodes


class LDAPUnsolicitedNotification(LDAPMessage):
    """A special kind of LDAPMessages which includes responses without former request.

    This may be used to signal an extraordinary condition in the server or in the LDAP
    session between the client and the server.
    """
    def __init__(self, operation: LDAPExtendedResponse, **kwargs: Any):
        super().__init__(msg_id=0, operation=operation)


@EXTENDED_RESPONSES.add
class LDAPNoticeOfDisconnection(LDAPExtendedResponse):
    """Note to the client that the server will terminate the LDAP session.

    Defined in Sec. 4.4.1. [RFC4511].
    """
    responseName = "1.3.6.1.4.1.1466.20036"
    responseValue = None

    def __init__(self, resultCode: ResultCodes, diagnosticMessage: str, **kwargs: Any):
        super().__init__(
            resultCode=resultCode,
            matchedDN=DistinguishedName(""),
            diagnosticMessage=diagnosticMessage,
            referral=None,
            responseName=self.responseName,
            responseValue=self.responseValue
        )
