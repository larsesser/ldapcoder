import abc
from typing import TYPE_CHECKING, Dict, Generic, Type, TypeVar

if TYPE_CHECKING:
    from ldapcoder.filter import LDAPFilter, LDAPFilter_substrings_string
    from ldapcoder.ldaputils import LDAPProtocolOp
    from ldapcoder.message import LDAPControl
    from ldapcoder.operations.bind import LDAPAuthenticationChoice
    from ldapcoder.operations.extended import LDAPExtendedRequest, LDAPExtendedResponse
    from ldapcoder.operations.intermediate import LDAPIntermediateResponse

KT = TypeVar("KT")
VT = TypeVar("VT")


class Registry(Generic[KT, VT]):
    """Store items and enable the end user of the library to add additional ones."""
    _items: Dict[KT, VT]

    def __init__(self) -> None:
        self._items = {}

    def __getitem__(self, item: KT) -> VT:
        return self._items[item]

    def __contains__(self, item: KT) -> bool:
        return item in self._items

    @abc.abstractmethod
    def add(self, item: VT) -> VT:
        """Add a new item to the storage. May also be used as decorator around class definition."""
        raise NotImplementedError


class ProtocolOperationsRegistry(Registry[int, Type["LDAPProtocolOp"]]):
    ProtocolOperation = TypeVar("ProtocolOperation", bound=Type["LDAPProtocolOp"])

    def add(self, item: ProtocolOperation) -> ProtocolOperation:
        if item.tag in self._items:
            raise RuntimeError
        self._items[item.tag] = item
        return item


PROTOCOL_OPERATIONS = ProtocolOperationsRegistry()


class ControlsRegistry(Registry[str, Type["LDAPControl"]]):
    Control = TypeVar("Control", bound=Type["LDAPControl"])

    def add(self, item: Control) -> Control:
        if item.controlType in self._items:
            raise RuntimeError
        self._items[item.controlType] = item
        return item


CONTROLS = ControlsRegistry()


class AuthenticationChoiceRegistry(Registry[int, Type["LDAPAuthenticationChoice"]]):
    AuthenticationChoice = TypeVar("AuthenticationChoice", bound=Type["LDAPAuthenticationChoice"])

    def add(self, item: AuthenticationChoice) -> AuthenticationChoice:
        if item.tag in self._items:
            raise RuntimeError
        self._items[item.tag] = item
        return item


AUTHENTICATION_CHOICES = AuthenticationChoiceRegistry()


class FilterRegistry(Registry[int, Type["LDAPFilter"]]):
    Filter = TypeVar("Filter", bound=Type["LDAPFilter"])

    def add(self, item: Filter) -> Filter:
        if item.tag in self._items:
            raise RuntimeError
        self._items[item.tag] = item
        return item


FILTERS = FilterRegistry()


class SubstringRegistry(Registry[int, Type["LDAPFilter_substrings_string"]]):
    Substring = TypeVar("Substring", bound=Type["LDAPFilter_substrings_string"])

    def add(self, item: Substring) -> Substring:
        if item.tag in self._items:
            raise RuntimeError
        self._items[item.tag] = item
        return item


SUBSTRINGS = SubstringRegistry()


class ExtendedRequestRegistry(Registry[str, Type["LDAPExtendedRequest"]]):
    ExtendedRequest = TypeVar("ExtendedRequest", bound=Type["LDAPExtendedRequest"])

    def add(self, item: ExtendedRequest) -> ExtendedRequest:
        if item.requestName in self._items:
            raise RuntimeError
        self._items[item.requestName] = item
        return item


EXTENDED_REQUESTS = ExtendedRequestRegistry()


class ExtendedResponseRegistry(Registry[str, Type["LDAPExtendedResponse"]]):
    ExtendedResponse = TypeVar("ExtendedResponse", bound=Type["LDAPExtendedResponse"])

    def add(self, item: ExtendedResponse) -> ExtendedResponse:
        if item.responseName in self._items:
            raise RuntimeError
        if item.responseName is None:
            raise RuntimeError
        self._items[item.responseName] = item
        return item


EXTENDED_RESPONSES = ExtendedResponseRegistry()


class IntermediateResponseRegistry(Registry[str, Type["LDAPIntermediateResponse"]]):
    IntermediateResponse = TypeVar("IntermediateResponse", bound=Type["LDAPIntermediateResponse"])

    def add(self, item: IntermediateResponse) -> IntermediateResponse:
        if item.responseName in self._items:
            raise RuntimeError
        if item.responseName is None:
            raise RuntimeError
        self._items[item.responseName] = item
        return item


INTERMEDIATE_RESPONSES = IntermediateResponseRegistry()
