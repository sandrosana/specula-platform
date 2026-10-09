from typing import Literal

from pydantic import BaseModel, Field

Role = Literal["viewer", "analyst", "admin"]


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
    # To send back in the X-CSRF-Token header of every write request.
    csrf_token: str
