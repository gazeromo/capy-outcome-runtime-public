"""Stable tool/input failures; details must never contain raw input or host data."""


class AcceptorError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(code)
