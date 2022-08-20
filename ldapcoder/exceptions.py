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
