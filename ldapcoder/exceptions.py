from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ldapcoder.result import LDAPResult


class EncodingError(Exception):
    pass


class DecodingError(Exception):
    pass


class InsufficientDataError(DecodingError):
    pass


class UnknownTagError(DecodingError):
    def __init__(self, tag: int) -> None:
        super().__init__()
        self.tag = tag

    def __str__(self) -> str:
        return f"Unknown tag {hex(self.tag)} in current context."


class DuplicateTagReceivedError(DecodingError):
    def __init__(self, description: str) -> None:
        super().__init__()
        self.description = description

    def __str__(self) -> str:
        return f"{self.description} received twice."


class HandlingError(Exception):
    """Terminate the handling of an LDAP request.

    This is used if the handling of an LDAP request needs to be prematurely terminated.
    The LDAPResult which would normally be replied to the client is stored here, to be
    sent to the client after caught at a higher level.
    """
    result: "LDAPResult"

    def __init__(self, result: "LDAPResult"):
        self.result = result
