from typing import Union
from fastapi import HTTPException
from pydantic import BaseModel
from ..db import db
import bcrypt
from uuid import uuid4
from datetime import datetime, timedelta
import jwt
import os


class SignupInputForm(BaseModel):
    username:str
    email:str
    password:str


    def save(self):
        password_bytes = self.password.encode()
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password_bytes, salt)
        password_hash = hash.decode()
        cursor = db.cursor()
        try:
            cursor.execute(
            'INSERT INTO users (id, username, email, password_hash) values (%s, %s, %s, %s)',
            [uuid4(), self.username, self.email, password_hash]
            )
            db.commit()
        except:
            raise HTTPException(406)


class LoginTokens(BaseModel):
    access_token:str
    refresh_token:str

class LoginInputForm(BaseModel):
    username:str
    password:str

    def check_password(self, password,password_hash):
        if bcrypt.checkpw(password.encode(), password_hash.encode()):
            return True

    def get_jwt_tokens(self)->Union[LoginTokens, None]:
        cursor = db.cursor()
        cursor.execute("SELECT id, password_hash from users where username = %s", [self.username]); 
        data = cursor.fetchone()
        if data is None:
            return None
        user_id, password_hash = data[0], data[1]
        if(self.check_password(self.password,password_hash)):
            access_token_payload = {
                "user_id": str(user_id) or None,
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(minutes=15)  # Adjust the expiration time as needed
            }
            access_token = jwt.encode(
                access_token_payload,
                os.environ.get("ACCESS_SECRET", "access_secret"),
                algorithm="HS256"
            )

            refresh_token_payload = {
                "user_id": str(user_id) or None,
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(days=7)  # Adjust the expiration time as needed
            }
            refresh_token = jwt.encode(
                refresh_token_payload,
                os.environ.get("REFRESH_SECRET", "refresh_secret"),
                algorithm="HS256"
            )

            return LoginTokens(access_token=access_token, refresh_token=refresh_token)
