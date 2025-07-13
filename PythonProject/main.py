from authx.types import SameSitePolicy
from fastapi import FastAPI, HTTPException, Depends, Response, Cookie, Request
from pydantic import BaseModel, EmailStr, Field
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import hashlib
from authx import AuthX, AuthXConfig
from datetime import datetime
import jwt
import uvicorn
#origins = [
 #   "http://localhost:5172",
 #   "http://127.0.0.1:5172",  # Исправлено: убрано дублирование http://
#]
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешает все домены
    allow_credentials=True,
    allow_methods=["*"],  # Разрешает все методы
    allow_headers=["*"],  # Разрешает все заголовки
)


DB_config = {
    "dbname": "states",
    "user": "postgres",
    "password": "753951asdD",
    "host": "localhost",
    "port": "5432"
}






config = AuthXConfig()
config.JWT_SECRET_KEY = "bebra"
config.JWT_ACCESS_COOKIE_NAME = "my_token"
config.JWT_COOKIE_CSRF_PROTECT = False
config.JWT_TOKEN_LOCATION = ["cookies"]
config.JWT_COOKIE_DOMAIN = "localhost"  # Должен совпадать с фронтендом
config.JWT_COOKIE_SAMESITE = "lax"      # Или "none" для HTTPS
config.JWT_COOKIE_SECURE = False        # True только для HTTPS


security = AuthX(config=config)

class RegistrationSchema(BaseModel):
    UserName: str
    Email: EmailStr
    password_first: str
    password_second: str





class PostSchema(BaseModel):
    header:str
    text: str
    owner: str


@app.post("/api/Registration")
async def Registration(user_data: RegistrationSchema, response: Response):

    try:
        if user_data.password_first != user_data.password_second:
            raise HTTPException(status_code=400, detail="Passwords don't match")
        with psycopg2.connect(**DB_config) as conn:
            with conn.cursor() as cursor:

                cursor.execute('SELECT * FROM users WHERE username = %s', (user_data.UserName,))
                flag_usr = cursor.fetchone()
                if flag_usr is not None:
                    raise HTTPException(status_code=409, detail="username already registered")
                cursor.execute('SELECT * FROM users WHERE email = %s', (user_data.Email,))
                flag_eml = cursor.fetchone()
                if flag_eml is not None:
                    raise HTTPException(status_code=409, detail='email already registered')
                password = user_data.password_second.encode()
                salt = 'my_salt'.encode()
                pass_heshed = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
                pass_heshed = pass_heshed.hex()

                id_user = int(datetime.now().timestamp() * 100000)
                role = 'admin'

                cursor.execute('INSERT INTO users (id_user, username, email, password, role) VALUES (%s, %s, %s, %s, %s)',
                                   (id_user, user_data.UserName, user_data.Email, pass_heshed, role))
                conn.commit()
                token = security.create_access_token(uid=(str(id_user)))
                response.set_cookie(config.JWT_ACCESS_COOKIE_NAME, token, max_age=3600*24*15)


    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500)

@app.get('/api/LoginAnonymous')
async def LoginAnonymous(response: Response, request: Request):
    id_anon_user = request.cookies.get(config.JWT_ACCESS_COOKIE_NAME)
    if id_anon_user is None:
        id_anon_user = int(datetime.now().timestamp() * 100000)
    with psycopg2.connect(**DB_config) as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO anonms (id_anon, count_comm) VALUES (%s, %s)', (
                id_anon_user, 0
            ))
            conn.commit()
    token = security.create_access_token(uid=(str(id_anon_user)))
    response.set_cookie(config.JWT_ACCESS_COOKIE_NAME, token, max_age=3600)




@app.get('/api/protected', dependencies=[Depends(security.access_token_required)])
async def get_protected():
    return {"message": "Hello World"}


class LoginSchema(BaseModel):
    Email: EmailStr
    password: str
@app.post("/api/Login")
async def Login(user_data: LoginSchema, response: Response):
    try:
        with psycopg2.connect(**DB_config) as conn:
            with conn.cursor() as cur:

                cur.execute('SELECT * FROM users WHERE email = %s', (user_data.Email,))
                password = cur.fetchone()
                print(password)
                salt = 'my_salt'.encode()
                if password is None:
                    raise HTTPException(status_code=409, detail='Email not registered')
                id_user = password[0]
                password = password[3]

                usr_hsd_pswd = hashlib.pbkdf2_hmac('sha256', user_data.password.encode(), salt, 100000).hex()
                if password != usr_hsd_pswd:
                    raise HTTPException(status_code=409, detail='password or login is incorrect')

                id_user = str(id_user)
                token = security.create_access_token(uid=id_user)
                response.set_cookie(config.JWT_ACCESS_COOKIE_NAME, token)
                return {token: password[0]}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500)


class StateSchema(BaseModel):
    title: str
    text: str

@app.post("/api/PostState", dependencies=[Depends(security.access_token_required)])
async def PostState(state: StateSchema, request: Request):

        if state.text == '' or state.title == '':
            raise HTTPException(status_code=409, detail='title or text of state in empty')
        token = request.cookies.get(config.JWT_ACCESS_COOKIE_NAME)
        id_owner = jwt.decode(token, key=config.JWT_SECRET_KEY, algorithms=["HS256"])
        id_owner = id_owner['sub']
        id_owner = int(id_owner)



        with psycopg2.connect(**DB_config) as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT * FROM anonms WHERE id_anon = %s', (id_owner,))
                anon_reg = cur.fetchone()
                if anon_reg is None:
                    id_state = int(datetime.now().timestamp() * 10000)
                    cur.execute('INSERT INTO states (id_state, title, text, id_owner) VALUES (%s, %s, %s, %s)',
                                (id_state, state.title, state.text, id_owner))
                    conn.commit()
                else:
                    raise HTTPException(status_code=403, detail='you are not authorized')
                return {"status": "ok"}


class CommSchema(BaseModel):
    text: str
    id_state: int

@app.post("/api/PostComm", dependencies=[Depends(security.access_token_required)])
async def PostComm(comm: CommSchema, request: Request):
    if comm.text == '':
        raise HTTPException(status_code=409, detail='text of state in empty')
    registered = True
    token = request.cookies.get(config.JWT_ACCESS_COOKIE_NAME)
    id_own_comm = jwt.decode(token, key=config.JWT_SECRET_KEY, algorithms=["HS256"])

    id_own_comm = id_own_comm['sub']
    print(id_own_comm)
    with psycopg2.connect(**DB_config) as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM users WHERE id_user = %s', (int(id_own_comm),))
            reg_or_not = cur.fetchone()
            if reg_or_not == None:
                registered = False


    id_comm = int(datetime.now().timestamp() * 10000)
    if registered == False:
        with psycopg2.connect(**DB_config) as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT * FROM anonms WHERE id_anon = %s', (int(id_own_comm),))
                count = cur.fetchone()[1]
                print(count)
                if count < 2:
                    cur.execute('UPDATE anonms SET count_comm = %s WHERE id_anon = %s',
                                (count + 1, int(id_own_comm)))
                    conn.commit()
                    cur.execute('INSERT INTO comms (id_comm, text, id_state, id_comm_owner) VALUES (%s, %s, %s, %s)',
                                (id_comm, comm.text, comm.id_state, id_own_comm))
                    conn.commit()
                else:
                    raise HTTPException(status_code=409, detail='Your limit exceeded')
    else:
        with psycopg2.connect(**DB_config) as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO comms (id_comm, text, id_state, id_comm_owner) VALUES (%s, %s, %s, %s)',
                                (id_comm, comm.text, comm.id_state, id_own_comm))
                conn.commit()


    return {"id_comm": id_comm,
            "text": comm.text,
            "id_state": comm.id_state,
            "id_own_comm": id_own_comm
            }
@app.get('/api/GetStates')
async def get_states(request: Request):
    try:
        json_states = []
        with psycopg2.connect(**DB_config) as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT id_state, title, text, id_owner, username FROM states JOIN users ON id_user = id_owner ORDER BY id_state DESC LIMIT 3;')

                states = cur.fetchall()
        for line in states:

            json_states.append(
             {
                "id_state": line[0],
                "title": line[1],
                "text": line[2],
                "id_owner": line[3],
                "username": line[4]
             })
        return json_states
    except:
        raise HTTPException(status_code=500)

@app.get('/api/GetComm/{id_state}')
async def get_comm(id_state: int):
    try:
        with psycopg2.connect(**DB_config) as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT id_comm, text, id_comm_owner, username FROM comms JOIN users ON id_comm_owner = id_user WHERE id_state = %s;',
                            (id_state,))
                comms = cur.fetchall()
        json_comms = []
        for line in comms:
            json_comms.append(
                {
                    "id_comm": line[0],
                    "text": line[1],
                    "id_comm_owner": line[2],
                    "username": line[3],
                })
        return json_comms
    except: raise HTTPException(status_code=500)










#@app.get("/addPost")
#async def addPost(post_data:PostSchema):
  #  try:





@app.get("/first")
async def first():
    return {"message": "bebra"}

