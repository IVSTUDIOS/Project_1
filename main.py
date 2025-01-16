import os
from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import jwt  # Use pyjwt instead of jose
from jwt.exceptions import PyJWTError  # Import the appropriate exception from pyjwt
from passlib.context import CryptContext
import sqlite3
import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from fastapi_cache2 import FastAPICache
from fastapi_cache2.backends.redis import RedisBackend
import aioredis
from fastapi.middleware.cors import CORSMiddleware

# Constants for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI app
app = FastAPI(
    title="EV Charging Station API",
    description="API for managing electric vehicle charging stations, users, and reservations.",
    version="1.0.0",
)

# Initialize Redis and FastAPI Cache
@app.on_event("startup")
async def startup():
    redis = aioredis.from_url("redis://localhost")
    FastAPICache.init(RedisBackend(redis), prefix="fastapi-cache")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database setup
def init_db():
    with sqlite3.connect("ev_charging.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'User'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'available'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                station_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'reserved',
                FOREIGN KEY (station_id) REFERENCES stations (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS role_permissions (
                role TEXT NOT NULL,
                permission_id INTEGER NOT NULL,
                FOREIGN KEY (role) REFERENCES users (role),
                FOREIGN KEY (permission_id) REFERENCES permissions (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                station_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                rating INTEGER NOT NULL,
                comment TEXT NOT NULL,
                FOREIGN KEY (station_id) REFERENCES stations (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
init_db()

# Define and add permissions
permissions = ["create_station", "view_station", "reserve_station", "manage_users"]

def add_permissions():
    with sqlite3.connect("ev_charging.db") as conn:
        cursor = conn.cursor()
        for permission in permissions:
            cursor.execute("INSERT OR IGNORE INTO permissions (name) VALUES (?)", (permission,))
        conn.commit()
add_permissions()

# Assign permissions to roles
role_permissions = {
    "Admin": ["create_station", "view_station", "reserve_station", "manage_users"],
    "User": ["view_station", "reserve_station"]
}

def assign_role_permissions():
    with sqlite3.connect("ev_charging.db") as conn:
        cursor = conn.cursor()
        for role, perms in role_permissions.items():
            for perm in perms:
                cursor.execute("""
                    INSERT OR IGNORE INTO role_permissions (role, permission_id)
                    SELECT ?, id FROM permissions WHERE name = ?
                """, (role, perm))
        conn.commit()
assign_role_permissions()

# Models
class User(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "User"

class Station(BaseModel):
    id: int
    name: str
    latitude: float
    longitude: float
    status: str

class NewStation(BaseModel):
    name: str
    latitude: float
    longitude: float
    status: str = "available"

class ReservationRequest(BaseModel):
    station_id: int
    user_id: int

class Reservation(BaseModel):
    id: int
    station_id: int
    user_id: int
    status: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class Review(BaseModel):
    station_id: int
    user_id: int
    rating: int
    comment: str

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(username: str):
    with sqlite3.connect("ev_charging.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return {"id": row[0], "username": row[1], "email": row[2], "password": row[3], "role": row[4]}
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = get_user(username)
        if user is None:
            raise HTTPException(
                status_code=401,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    except PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "User":
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user

async def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user

# Check permissions
def get_permission_id(permission_name: str):
    with sqlite3.connect("ev_charging.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM permissions WHERE name = ?", (permission_name,))
        row = cursor.fetchone()
        if row:
            return row[0]
    return None

async def check_permission(current_user: dict, permission_name: str):
    permission_id = get_permission_id(permission_name)
    if not permission_id:
        raise HTTPException(status_code=400, detail="Permission not found")

    with sqlite3.connect("ev_charging.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 1 FROM role_permissions
            WHERE role = ? AND permission_id = ?
        """, (current_user["role"], permission_id))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=403, detail="Not authorized")

# Routes
@app.get("/", response_class=HTMLResponse, summary="Home Page", description="Displays the home page.")
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/admin", response_class=HTMLResponse, summary="Admin Dashboard", description="Displays the admin dashboard.")
@limiter.limit("5/minute")
async def admin_dashboard(request: Request, current_user: dict = Depends(get_current_admin_user)):
    try:
        with sqlite3.connect("ev_charging.db") as conn:
            cursor = conn.cursor()
            
            # Fetch users
            cursor.execute("SELECT id, username, email, role FROM users")
            users = cursor.fetchall()
            users = [{"id": row[0], "username": row[1], "email": row[2], "role": row[3]} for row in users]
            
            # Fetch stations
            cursor.execute("SELECT id, name, latitude, longitude, status FROM stations")
            stations = cursor.fetchall()
            stations = [{"id": row[0], "name": row[1], "latitude": row[2], "longitude": row[3], "status": row[4]} for row in stations]
            
            # Fetch reservations
            cursor.execute("SELECT id, station_id, user_id, status FROM reservations")
            reservations = cursor.fetchall()
            reservations = [{"id": row[0], "station_id": row[1], "user_id": row[2], "status": row[3]} for row in reservations]
            
            return templates.TemplateResponse("admin_dashboard.html", {"request": request, "users": users, "stations": stations, "reservations": reservations})
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error loading admin dashboard: " + str(e))

@app.post("/signup", response_model=User, summary="User Signup", description="Registers a new user.")
@limiter.limit("5/minute")
def signup(user: User):
    try:
        with sqlite3.connect("ev_charging.db") as conn:
            cursor = conn.cursor()
            hashed_password = get_password_hash(user.password)
            cursor.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (user.username, user.email, hashed_password, user.role),
            )
            conn.commit()
            return {"message": "User registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error signing up: " + str(e))

@app.post("/token", response_model=Token, summary="User Login", description="Generates an access token for user login.")
@limiter.limit("5/minute")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/stations", response_model=List[Station], summary="Get Stations", description="Retrieves a list of all charging stations.")
@limiter.limit("10/minute")
async def get_stations(current_user: dict = Depends(get_current_active_user)):
    await check_permission(current_user, "view_station")
    try:
        with sqlite3.connect("ev_charging.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM stations")
            rows = cursor.fetchall()
            return [Station(id=row[0], name=row[1], latitude=row[2], longitude=row[3], status=row[4]) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error retrieving stations: " + str(e))

@app.get("/stations_map", response_class=HTMLResponse, summary="Stations Map", description="Displays a map of all charging stations.")
@limiter.limit("10/minute")
def stations_map(request: Request):
    return templates.TemplateResponse("stations_map.html", {"request": request})

@app.post("/reservations", response_model=Reservation, summary="Create Reservation", description="Creates a new reservation for a charging station.")
@limiter.limit("5/minute")
async def create_reservation(reservation_request: ReservationRequest, current_user: dict = Depends(get_current_active_user)):
    await check_permission(current_user, "reserve_station")
    try:
        with sqlite3.connect("ev_charging.db") as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO reservations (station_id, user_id, status) VALUES (?, ?, ?)",
                (reservation_request.station_id, current_user["id"], "reserved"),
            )
            conn.commit()
            return Reservation(id=cursor.lastrowid, station_id=reservation_request.station_id, user_id=current_user["id"], status="reserved")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error creating reservation: " + str(e))

@app.get("/reservations/history", response_model=List[Reservation], summary="Reservation History", description="Retrieves the reservation history for the current user.")
@limiter.limit("5/minute")
async def get_reservation_history(current_user: dict = Depends(get_current_active_user)):
    try:
        with sqlite3.connect("ev_charging.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reservations WHERE user_id = ?", (current_user["id"],))
            rows = cursor.fetchall()
            return [Reservation(id=row[0], station_id=row[1], user_id=row[2], status=row[3]) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error retrieving reservation history: " + str(e))

@app.put("/users/me", response_model=User, summary="Update User Profile", description="Updates the profile of the current user.")
@limiter.limit("5/minute")
async def update_user_profile(user: User, current_user: dict = Depends(get_current_active_user)):
    try:
        with sqlite3.connect("ev_charging.db") as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET email = ?, password = ? WHERE id = ?",
                (user.email, get_password_hash(user.password), current_user["id"]),
            )
            conn.commit()
            return user
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error updating profile: " + str(e))