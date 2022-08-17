from typing import Any

from ldapcoder.ldaputils import LDAPProtocolOp, check
from ldapcoder.message import LDAPMessage
from ldapcoder.operations.extended import EXTENDED_RESPONSES, LDAPExtendedResponse
from ldapcoder.result import ResultCodes


class LDAPUnsolicitedNotification(LDAPMessage):
    def __init__(self, operation: "LDAPProtocolOp", **kwargs: Any):
        check(isinstance(operation, LDAPExtendedResponse))
        super().__init__(msg_id=0, operation=operation)


@EXTENDED_RESPONSES.add
class LDAPExtendedResponse_NoticeOfDisconnection(LDAPExtendedResponse):
    responseName = "1.3.6.1.4.1.1466.20036"
    responseValue = None

    def __init__(self, resultCode: ResultCodes, diagnosticMessage: str, **kwargs: Any):
        super().__init__(
            resultCode=resultCode,
            matchedDN="",
            diagnosticMessage=diagnosticMessage,
            referral=None,
            responseName=self.responseName,
            responseValue=self.responseValue
        )
