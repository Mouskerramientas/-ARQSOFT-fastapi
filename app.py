import re
from typing import Annotated
from bcrypt import checkpw, gensalt, hashpw
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Enum, Field, Session, SQLModel, create_engine, select
from jose import jwt

from dotenv import load_dotenv
import os

load_dotenv()

DB_NAME = os.getenv("POSTGRES_DB")
DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = "db"
DB_PORT = 5432

# Cambiar la configuración de conexión
postgres_url = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# postgres_url = "postgresql://myuser:mysecretpassword@localhost:5432/mydatabase"
engine = create_engine(postgres_url)

connect_args = {"check_same_thread": False}

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str
    password: str
    type: str = "client"
    email: str

class EstadoServicio(str, Enum):
    activo = "Activo"
    inactivo = "Inactivo"

class Servicio(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nombre: str
    descripcion: str
    user_id: int | None = Field(foreign_key="user.id")
    estado: str = "activo"

class Servidor(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nombre: str
    user_id: int = Field(foreign_key="user.id")

class Failure(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    nombre: str
    descripcion: str
    user_id: int = Field(foreign_key="user.id")
    servicio_id: int = Field(foreign_key="servicio.id")
    servidor_id: int = Field(foreign_key="servidor.id")


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
    try:
        data = jwt.decode(token, "my-api-secret-key", algorithms=["HS256"])
    except jwt.JWTError:
        raise HTTPException(status_code=403, detail="Token invalido")
    return data

def hash_password(password: str) -> str:
    return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def user_is_admin(user: Annotated[dict, Depends(decode_token)]) -> bool:
    user_info = Session(engine).exec(select(User).where(User.username == user["username"])).first()
    if user_info.type == "admin":
        return True
    else:
        raise HTTPException(status_code=403, detail="Forbidden")
    
def user_type(user: Annotated[dict, Depends(decode_token)]) -> str:
    user_info = Session(engine).exec(select(User).where(User.username == user["username"])).first()
    return {
        "type": user_info.type,
        "id": user_info.id
    }

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

#! Not allowed to Client user
@app.post("/users/")
def create_user(user: User, _: Annotated[bool, Depends(user_is_admin)], session: SessionDep) -> User:
    # Crear el usuario en la base de datos
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

#! Not allowed to Client user
@app.get("/users/")
def read_users(
    _: Annotated[bool, Depends(user_is_admin)],  # Proteger con autenticación
    session: SessionDep
) -> list[User]:
    # Obtener todos los usuarios de la base de datos
    print("Se conectó un usuario administrador")
    users = session.exec(select(User)).all()
    return users

#! Client user can only access to his user
@app.get("/users/{user_id}")
def read_user(user_id: int, user_session: Annotated[dict, Depends(user_type)], session: SessionDep) -> User:

    user = session.get(User, user_session["id"])

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user_session["type"] != "admin" and user_id != user_session["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    else:
        return user

#! Client user can only access to his user
@app.put("/users/{user_id}")
def update_user(user_id:int, user_session: Annotated[dict, Depends(user_type)], user: User, session: SessionDep) -> User:

    db_user = session.get(User, user_id)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user_session["type"] != "admin" and db_user.id != user_session["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    else:
        setattr(db_user, "username", user.username)
        setattr(db_user, "password", user.password)
        setattr(db_user, "email", user.email)
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return db_user

#! Not allowed to Client user
@app.delete("/users/{user_id}")
def delete_user(user_id: int, _: Annotated[bool, Depends(user_is_admin)], session: SessionDep):
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

#! Un cliente solo puede registrar servicios con su id
@app.post("/servicios/")
def create_servicio(servicio: Servicio, user: Annotated[dict, Depends(user_type)], session: SessionDep) -> Servicio:
    servicio.user_id = user["id"]
    session.add(servicio)
    session.commit()
    session.refresh(servicio)
    return servicio

#! Un cliente solo puede ver SUS servicios
@app.get("/servicios/")
def read_servicios(user: Annotated[dict, Depends(user_type)],  session: SessionDep) -> list[Servicio]:
    if user["type"] == "admin":
        servicios = session.exec(select(Servicio)).all()
        return servicios
    else:
        servicios = session.exec(select(Servicio).where(Servicio.user_id == user["id"])).all()
        return servicios

#! Un cliente solo puede leer un servicio si su id corresponde con el del dueño del servicio
@app.get("/servicios/{servicio_id}")
def read_servicio(servicio_id: int, user: Annotated[dict, Depends(user_type)], session: SessionDep) -> Servicio:
    servicio = session.get(Servicio, servicio_id)
    if not servicio:
        raise HTTPException(status_code=404, detail="Servicio not found")
    
    if user["type"] != "admin" and servicio.user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    else:
        return servicio

#! Un cliente solo puede actualizar un servicio si su id corresponde con el del dueño del servicio
@app.put("/servicios/{servicio_id}")
def update_servicio(servicio_id: int, user: Annotated[dict, Depends(user_type)], servicio: Servicio, session: SessionDep) -> Servicio:
    db_servicio = session.get(Servicio, servicio_id)
    if not db_servicio:
        raise HTTPException(status_code=404, detail="Servicio not found")
    
    if user["type"] != "admin" and db_servicio.user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    else:
        setattr(db_servicio, "nombre", servicio.nombre)
        setattr(db_servicio, "descripcion", servicio.descripcion)
        session.add(db_servicio)
        session.commit()
        session.refresh(db_servicio)
        return db_servicio

#! Un cliente no puede eliminar un servicio
@app.delete("/servicios/{servicio_id}")
def delete_servicio(servicio_id: int, _: Annotated[dict, Depends(user_is_admin)], session: SessionDep):
    servicio = session.get(Servicio, servicio_id)
    if not servicio:
        raise HTTPException(status_code=404, detail="Servicio not found")
    session.delete(servicio)
    session.commit()
    return {"ok": True}

"""
CRUD Routes for Servidor
"""

#! Un cliente solo puede registrar servidores con su id
@app.post("/servidores/")
def create_servidor(servidor: Servidor, user: Annotated[dict, Depends(user_type)], session: SessionDep) -> Servidor:
    servidor.user_id = user["id"]
    session.add(servidor)
    session.commit()
    session.refresh(servidor)
    return servidor

#! Un cliente solo puede ver SUS servidores
@app.get("/servidores/")
def read_servidores(user: Annotated[dict, Depends(user_type)]  ,session: SessionDep) -> list[Servidor]:
    if user["type"] == "admin":
        servidores = session.exec(select(Servidor)).all()
        return servidores
    else:
        servidores = session.exec(select(Servidor).where(Servidor.user_id == user["id"])).all()
        return servidores

#! Un cliente solo puede leer un servidor si su id corresponde con el del dueño del servidor
@app.get("/servidores/{servidor_id}")
def read_servidor(servidor_id: int, user: Annotated[dict, Depends(user_type)], session: SessionDep) -> Servidor:
    servidor = session.get(Servidor, servidor_id)
    
    if not servidor:
        raise HTTPException(status_code=404, detail="Servidor not found")
    
    if user["type"] != "admin" and servidor.user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    else:
        return servidor


#! Un cliente solo puede actualizar un servidor si su id corresponde con el del dueño del servidor
@app.put("/servidores/{servidor_id}")
def update_servidor(servidor_id: int, user:Annotated[dict, Depends(user_type)], servidor: Servidor, session: SessionDep) -> Servidor: 
    db_servidor = session.get(Servidor, servidor_id)
    if not db_servidor:
        raise HTTPException(status_code=404, detail="Servidor not found")
    
    if user["type"] != "admin" and db_servidor.user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    else:
        setattr(db_servidor, "nombre", servidor.nombre)
        session.add(db_servidor)
        session.commit()
        session.refresh(db_servidor)
        return db_servidor

#! Un cliente no puede eliminar un servidor
@app.delete("/servidores/{servidor_id}")
def delete_servidor(servidor_id: int, _:Annotated[dict, Depends(user_is_admin)], session: SessionDep):
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
def create_failure(failure: Failure, _:Annotated[dict, Depends(user_is_admin)], session: SessionDep) -> Failure:
    session.add(failure)
    session.commit()
    session.refresh(failure)
    return failure

@app.get("/failures/")
def read_failures(user: Annotated[dict, Depends(user_type)], session: SessionDep) -> list[Failure]:
    if user["type"] == "admin":
        failures = session.exec(select(Failure)).all()
        return failures
    else:
        failures = session.exec(select(Failure).where(Failure.user_id == user["id"])).all()
        return failures

@app.get("/failures/{failure_id}")
def read_failure(failure_id: int, user:Annotated[dict, Depends(user_type)], session: SessionDep) -> Failure:
    failure = session.get(Failure, failure_id)
    if not failure:
        raise HTTPException(status_code=404, detail="Failure not found")
    if user["type"] != "admin" and failure.user_id != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    else:
        return failure

#! El método PUT no está permitido
# @app.put("/failures/{failure_id}")
# def update_failure(failure_id: int, _:Annotated[dict, Depends(decode_token)], failure: Failure, session: SessionDep) -> Failure:
#     db_failure = session.get(Failure, failure_id)
#     if not db_failure:
#         raise HTTPException(status_code=404, detail="Failure not found")
#     setattr(db_failure, "nombre", failure.nombre)
#     setattr(db_failure, "descripcion", failure.descripcion)
#     session.add(db_failure)
#     session.commit()
#     session.refresh(db_failure)
#     return db_failure

#! El método DELETE no está permitido
# @app.delete("/failures/{failure_id}")
# def delete_failure(failure_id: int, _:Annotated[dict, Depends(decode_token)], session: SessionDep):
#     failure = session.get(Failure, failure_id)
#     if not failure:
#         raise HTTPException(status_code=404, detail="Failure not found")
#     session.delete(failure)
#     session.commit()
#     return {"ok": True}
