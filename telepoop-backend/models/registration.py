from pydantic import BaseModel

class RegistrationDetail(BaseModel):
    username: str
    password: str
    security_token: str