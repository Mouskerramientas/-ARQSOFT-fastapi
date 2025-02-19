import re
from typing import Annotated

from bcrypt import checkpw, gensalt, hashpw
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Field, Session, SQLModel, create_engine, select
from jose import jwt

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str
    password: str
    email: str

class Servicio(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nombre: str
    descripcion: str
    user_id: int = Field(foreign_key="user.id")

class Servidor(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nombre: str
    user_id: int = Field(foreign_key="user.id")

class Failure(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nombre: str
    descripcion: str
    user_id: int = Field(foreign_key="user.id")


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]

app = FastAPI()


@app.on_event("startup")
def on_startup():
    create_db_and_tables()

"""
# Servicio de Autenticación
"""

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def encode_token(payload: dict) -> str:
    token = jwt.encode(payload, "my-api-secret-key", algorithm="HS256")
    return token

def decode_token(token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    data = jwt.decode(token, "my-api-secret-key", algorithms=["HS256"])
    return data

def hash_password(password: str) -> str:
    return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

"""
Rutas para el servicio de login
"""

@app.post("/token")
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep) -> dict:
    # user = users.get(form_data.username)
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = encode_token({"username": user.username, "email": user.email})
    return {"access_token": token}

@app.post("/users/register")
def register(username: str, password: str, email: str, session: SessionDep) -> dict:
    # if username in users:
    if session.exec(select(User).where(User.username == username)).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise HTTPException(status_code=400, detail="Invalid email")
    hashed_password = hash_password(password)
    user = User(username=username, password=hashed_password, email=email)
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"message": "User registered successfully"}


"""
# Servicio de Almacenamiento
"""

"""
CRUD Routes for User
"""

@app.post("/users/")
def create_user(user: User, _: Annotated[dict, Depends(decode_token)], session: SessionDep) -> User:
    # Crear el usuario en la base de datos
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@app.get("/users/")
def read_users(
    _: Annotated[dict, Depends(decode_token)],  # Proteger con autenticación
    session: SessionDep
) -> list[User]:
    # Obtener todos los usuarios de la base de datos
    users = session.exec(select(User)).all()
    return users

@app.get("/users/{user_id}")
def read_user(user_id: int, _: Annotated[dict, Depends(decode_token)], session: SessionDep) -> User:
    # Buscar el usuario en la base de datos
    user = session.get(User, user_id)
    # Si no se encuentra el usuario, lanzar un error 404
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Si lo encuentra, devolver el usuario
    return user

@app.put("/users/{user_id}")
def update_user(user_id:int, _: Annotated[dict, Depends(decode_token)], user: User, session: SessionDep) -> User:
    # Buscar el usuario en la base de datos
    db_user = session.get(User, user_id)
    # Si no se encuentra el usuario, lanzar un error 404
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    # Actualizar los datos del usuario
    setattr(db_user, "username", user.username)
    setattr(db_user, "password", user.password)
    setattr(db_user, "email", user.email)
    # Guardar los cambios en la base de datos
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@app.delete("/users/{user_id}")
def delete_user(user_id: int, _: Annotated[dict, Depends(decode_token)], session: SessionDep):
    # Buscar el usuario en la base de datos
    user = session.get(User, user_id)
    # Si no se encuentra el usuario, lanzar un error 404
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Eliminar el usuario de la base de datos
    session.delete(user)
    session.commit()
    return {"ok": True}

"""
CRUD Routes for Servicio
"""

@app.post("/servicios/")
def create_servicio(servicio: Servicio, _: Annotated[dict, Depends(decode_token)], session: SessionDep) -> Servicio:
    session.add(servicio)
    session.commit()
    session.refresh(servicio)
    return servicio

@app.get("/servicios/")
def read_servicios(_: Annotated[dict, Depends(decode_token)],  session: SessionDep) -> list[Servicio]:
    servicios = session.exec(select(Servicio)).all()
    return servicios

@app.get("/servicios/{servicio_id}")
def read_servicio(servicio_id: int, _: Annotated[dict, Depends(decode_token)], session: SessionDep) -> Servicio:
    servicio = session.get(Servicio, servicio_id)
    if not servicio:
        raise HTTPException(status_code=404, detail="Servicio not found")
    return servicio

@app.put("/servicios/{servicio_id}")
def update_servicio(servicio_id: int, _: Annotated[dict, Depends(decode_token)], servicio: Servicio, session: SessionDep) -> Servicio:
    db_servicio = session.get(Servicio, servicio_id)
    if not db_servicio:
        raise HTTPException(status_code=404, detail="Servicio not found")
    setattr(db_servicio, "nombre", servicio.nombre)
    setattr(db_servicio, "descripcion", servicio.descripcion)
    session.add(db_servicio)
    session.commit()
    session.refresh(db_servicio)
    return db_servicio

@app.delete("/servicios/{servicio_id}")
def delete_servicio(servicio_id: int, _: Annotated[dict, Depends(decode_token)], session: SessionDep):
    servicio = session.get(Servicio, servicio_id)
    if not servicio:
        raise HTTPException(status_code=404, detail="Servicio not found")
    session.delete(servicio)
    session.commit()
    return {"ok": True}

"""
CRUD Routes for Servidor
"""

@app.post("/servidores/")
def create_servidor(servidor: Servidor, _: Annotated[dict, Depends(decode_token)], session: SessionDep) -> Servidor:
    session.add(servidor)
    session.commit()
    session.refresh(servidor)
    return servidor

@app.get("/servidores/")
def read_servidores(_: Annotated[dict, Depends(decode_token)]  ,session: SessionDep) -> list[Servidor]:
    servidores = session.exec(select(Servidor)).all()
    return servidores

@app.get("/servidores/{servidor_id}")
def read_servidor(servidor_id: int, _: Annotated[dict, Depends(decode_token)], session: SessionDep) -> Servidor:
    servidor = session.get(Servidor, servidor_id)
    if not servidor:
        raise HTTPException(status_code=404, detail="Servidor not found")
    return servidor

@app.put("/servidores/{servidor_id}")
def update_servidor(servidor_id: int, _:Annotated[dict, Depends(decode_token)], servidor: Servidor, session: SessionDep) -> Servidor:
    db_servidor = session.get(Servidor, servidor_id)
    if not db_servidor:
        raise HTTPException(status_code=404, detail="Servidor not found")
    setattr(db_servidor, "nombre", servidor.nombre)
    session.add(db_servidor)
    session.commit()
    session.refresh(db_servidor)
    return db_servidor

@app.delete("/servidores/{servidor_id}")
def delete_servidor(servidor_id: int, _:Annotated[dict, Depends(decode_token)], session: SessionDep):
    servidor = session.get(Servidor, servidor_id)
    if not servidor:
        raise HTTPException(status_code=404, detail="Servidor not found")
    session.delete(servidor)
    session.commit()
    return {"ok": True}

"""
CRUD Routes for Failure
"""

@app.post("/failures/")
def create_failure(failure: Failure, _:Annotated[dict, Depends(decode_token)], session: SessionDep) -> Failure:
    session.add(failure)
    session.commit()
    session.refresh(failure)
    return failure

@app.get("/failures/")
def read_failures(_: Annotated[dict, Depends(decode_token)]  , session: SessionDep) -> list[Failure]:
    failures = session.exec(select(Failure)).all()
    return failures

@app.get("/failures/{failure_id}")
def read_failure(failure_id: int, _:Annotated[dict, Depends(decode_token)], session: SessionDep) -> Failure:
    failure = session.get(Failure, failure_id)
    if not failure:
        raise HTTPException(status_code=404, detail="Failure not found")
    return failure

@app.put("/failures/{failure_id}")
def update_failure(failure_id: int, _:Annotated[dict, Depends(decode_token)], failure: Failure, session: SessionDep) -> Failure:
    db_failure = session.get(Failure, failure_id)
    if not db_failure:
        raise HTTPException(status_code=404, detail="Failure not found")
    setattr(db_failure, "nombre", failure.nombre)
    setattr(db_failure, "descripcion", failure.descripcion)
    session.add(db_failure)
    session.commit()
    session.refresh(db_failure)
    return db_failure

@app.delete("/failures/{failure_id}")
def delete_failure(failure_id: int, _:Annotated[dict, Depends(decode_token)], session: SessionDep):
    failure = session.get(Failure, failure_id)
    if not failure:
        raise HTTPException(status_code=404, detail="Failure not found")
    session.delete(failure)
    session.commit()
    return {"ok": True}


