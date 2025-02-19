from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from fastapi.exceptions import HTTPException
from jose import jwt
import json
from pathlib import Path
from bcrypt import hashpw, gensalt, checkpw
from pydantic import BaseModel
import re

"""
Integrantes del grupo:
- Karol Guerrero
- Nicolás Rodríguez
- Fabián Rincón
- Daniel Velasco
"""

class Items(BaseModel):
    name: str
    description: str | None = None
    price: float
    tax: float | None = None


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

users_file = Path("users.json")

def load_users():
    if users_file.exists():
        with open(users_file, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(users_file, "w") as f:
        json.dump(users, f)

users = load_users()

def enconde_token(payload: dict) -> str:
    token = jwt.encode(payload, "my-secret-key", algorithm="HS256")
    return token

def decode_token(token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    data = jwt.decode(token, "my-secret-key", algorithms=["HS256"])
    return data

def hash_password(password: str) -> str:
    return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.post("/token")
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = users.get(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = enconde_token({"username": user["username"], "email": user["email"]})
    return {"access_token": token}

@app.post("/users/register")
def register(username: str, password: str, email: str):
    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise HTTPException(status_code=400, detail="Invalid email")
    hashed_password = hash_password(password)
    users[username] = {"username": username, "password": hashed_password, "email": email, "items": []}
    save_users(users)
    load_users()
    return {"message": "User registered successfully"}

@app.get("/users/items")
def profile(my_user: Annotated[dict, Depends(decode_token)]):
    user = users.get(my_user["username"])
    return user["items"]

@app.post("/users/items")
def create_item(my_user: Annotated[dict, Depends(decode_token)], item: Items):
    users[my_user["username"]]["items"].append(item.dict())
    save_users(users)
    return item
