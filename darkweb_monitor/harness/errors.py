"""Structured error taxonomy: a stable ``code`` distinct from the message."""
from __future__ import annotations


class HarnessError(Exception):
    code = "UNKNOWN"
    retryable = False

    def __init__(self, message: str = "", *, code: str | None = None, retryable: bool | None = None):
        super().__init__(message or self.__class__.__name__)
        if code:
            self.code = code
        if retryable is not None:
            self.retryable = retryable

    def as_dict(self) -> dict:
        return {"name": type(self).__name__, "code": self.code, "message": str(self), "retryable": self.retryable}


class ToolArgsError(HarnessError):
    code = "INVALID_ARGUMENTS"


class UnknownTool(HarnessError):
    code = "UNKNOWN_TOOL"


class ToolDenied(HarnessError):
    code = "DENIED"


class ApprovalPending(HarnessError):
    code = "APPROVAL_PENDING"

    def __init__(self, message: str, approval_id: int):
        super().__init__(message)
        self.approval_id = approval_id


class ToolTimeout(HarnessError):
    code = "TIMEOUT"
    retryable = True


class NotFound(HarnessError):
    code = "NOT_FOUND"


class Upstream(HarnessError):
    code = "UPSTREAM"
    retryable = True


class LlmError(HarnessError):
    code = "LLM_ERROR"
    retryable = True


class BudgetExceeded(HarnessError):
    code = "BUDGET_EXCEEDED"


class Cancelled(HarnessError):
    code = "CANCELLED"


def to_harness_error(exc: BaseException) -> HarnessError:
    if isinstance(exc, HarnessError):
        return exc
    err = HarnessError(f"{type(exc).__name__}: {exc}", code="INTERNAL")
    err.__cause__ = exc
    return err
