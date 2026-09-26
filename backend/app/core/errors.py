"""User-facing error model.

Every error that reaches the browser is an :class:`AppError` rendered as::

    {"error": {"code": "...", "title": "...", "message": "...", "action": "..."}}

Raw Python exceptions are never shown to users; unexpected exceptions become a generic
``INTERNAL_ERROR`` with a reference id that can be looked up in the server log.
"""

from __future__ import annotations


class AppError(Exception):
    status_code = 400
    code = "BAD_REQUEST"
    title = "Request failed"

    def __init__(
        self,
        message: str,
        *,
        title: str | None = None,
        code: str | None = None,
        action: str | None = None,
        status_code: int | None = None,
        details: dict | None = None,
        category: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if title:
            self.title = title
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code
        self.action = action
        self.details = details or {}
        self.category = category

    def to_dict(self) -> dict:
        from app.core.error_categories import _BY_CODE

        body = {"code": self.code, "title": self.title, "message": self.message}
        category = self.category or (_BY_CODE[self.code].value if self.code in _BY_CODE
                                     else None)
        if category:
            body["category"] = category  # safe error category (core/error_categories)
        if self.action:
            body["action"] = self.action
        if self.details:
            body["details"] = self.details
        return {"error": body}


class NotFoundError(AppError):
    status_code = 404
    code = "NOT_FOUND"
    title = "Not found"


class ConflictError(AppError):
    status_code = 409
    code = "CONFLICT"
    title = "Conflict"


class AuthenticationError(AppError):
    status_code = 401
    code = "NOT_AUTHENTICATED"
    title = "Authentication required"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "FORBIDDEN"
    title = "Permission denied"


class RateLimitedError(AppError):
    status_code = 429
    code = "RATE_LIMITED"
    title = "Too many requests"


class ValidationFailedError(AppError):
    status_code = 422
    code = "VALIDATION_FAILED"
    title = "Invalid input"
