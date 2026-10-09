from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator

Role = Literal["viewer", "analyst", "admin"]
# verify: type the code; enroll: set up the authenticator app first.
MfaState = Literal["verify", "enroll"]


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    # Upper bound only: the rules apply when a password is set, not when it is typed.
    password: str = Field(min_length=1, max_length=1024)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class MeOut(BaseModel):
    id: int
    email: str
    role: Role
    must_change_password: bool
    # Set while the session waits for the Admin's second factor: data stays closed.
    mfa_required: MfaState | None
    # To send back in the X-CSRF-Token header of every write request.
    csrf_token: str


class TotpSetupOut(BaseModel):
    # Base32 secret for manual entry and the otpauth:// URI for the QR code.
    secret: str
    otpauth_uri: str


class TotpActivateIn(BaseModel):
    code: str = Field(min_length=6, max_length=16)


class TotpActivatedOut(BaseModel):
    user: MeOut
    # Shown only now: each one replaces a code once if the phone is lost.
    recovery_codes: list[str]


class TotpVerifyIn(BaseModel):
    code: str | None = Field(default=None, min_length=6, max_length=16)
    recovery_code: str | None = Field(default=None, min_length=10, max_length=32)

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        if (self.code is None) == (self.recovery_code is None):
            raise ValueError("send either code or recovery_code")
        return self
