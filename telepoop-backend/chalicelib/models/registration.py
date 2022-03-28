from pydantic import BaseModel


class RegistrationDetail(BaseModel):
    username: str
    password: str
    security_token: str


class EncodedPassword(BaseModel):
    hash_method: str
    salt: bytes
    rounds: int
    hashed: bytes