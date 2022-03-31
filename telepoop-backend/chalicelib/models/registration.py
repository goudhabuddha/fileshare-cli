from pydantic import BaseModel, SecretStr, SecretBytes, ValidationError, validator

class RegistrationDetail(BaseModel):
    username: SecretStr
    password: SecretStr
    security_token: SecretStr

    @validator('username')
    def name_min_length(cls, v: str):
        min_length = 4
        if len(v) < min_length:
            raise ValidationError(f'Username must be greater than {min_length} characters.')
    
    @validator('password')
    def name_min_length(cls, v: str):
        min_length = 8
        if len(v) < min_length:
            raise ValidationError(f'Password must be greater than {min_length} characters.')


class EncodedPassword(BaseModel):
    hash_method: str
    salt: SecretBytes
    rounds: int
    hashed: SecretBytes