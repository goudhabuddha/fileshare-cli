from pydantic import BaseModel, SecretStr
from datetime import datetime

class AuthDetail(BaseModel):
    username: SecretStr
    password: SecretStr


class JWTDecoded(BaseModel):
    sub: SecretStr
    iat: datetime
    nbf: datetime
    exp: datetime
    jti: SecretStr