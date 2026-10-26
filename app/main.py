from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import jwt
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, field_validator
from pwdlib import PasswordHash

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(os.getenv("DATA_DIR", PROJECT_DIR / "data"))
DATA_FILE = DATA_DIR / "state.json"

_RAW_JWT_SECRET = os.getenv("JWT_SECRET")
JWT_SECRET = _RAW_JWT_SECRET or secrets.token_urlsafe(64)
JWT_SECRET_EPHEMERAL = _RAW_JWT_SECRET is None
if _RAW_JWT_SECRET is not None and len(_RAW_JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET должен содержать не менее 32 символов")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
OVERPASS_URL = os.getenv("OVERPASS_URL", "https://overpass-api.de/api/interpreter")
OVERPASS_CACHE_SECONDS = int(os.getenv("OVERPASS_CACHE_SECONDS", "90"))
MAX_BBOX_AREA = float(os.getenv("MAX_BBOX_AREA", "0.5"))

password_hash = PasswordHash.recommended()


class JsonStore:
    """Небольшое файловое хранилище для бета-версии без СУБД."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = asyncio.Lock()
        self.state: dict[str, Any] = {
            "users": {},
            "friendships": {},
            "locations": {},
        }

    async def load(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            await self.save()
            return
        try:
            self.state = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raise RuntimeError(f"Не удалось прочитать файл данных: {self.path}")

    async def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.state, ensure_ascii=False, indent=2)
        fd, tmp_name = tempfile.mkstemp(prefix="state_", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                tmp_file.write(payload)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)


store = JsonStore(DATA_FILE)
overpass_cache: dict[str, tuple[float, dict[str, Any]]] = {}
login_failures: dict[str, list[float]] = {}
http_client: httpx.AsyncClient | None = None


class RegisterBody(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = " ".join(value.strip().split())
        if not value:
            raise ValueError("Имя не может быть пустым")
        return value


class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LocationBody(BaseModel):
    lat: float = Field(ge=-90, le=90)
    lng: float = Field(ge=-180, le=180)
    accuracy: float | None = Field(default=None, ge=0, le=100_000)


class FriendRequestBody(BaseModel):
    email: EmailStr


class PrivacyBody(BaseModel):
    share_location: bool


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "share_location": user.get("share_location", True),
    }


def create_access_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "jti": secrets.token_urlsafe(12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def set_auth_cookies(response: Response, token: str) -> None:
    csrf_token = secrets.token_urlsafe(32)
    max_age = ACCESS_TOKEN_MINUTES * 60
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=max_age,
        path="/",
    )
    response.set_cookie(
        "csrf_token",
        csrf_token,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=max_age,
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("csrf_token", path="/")


async def get_current_user(access_token: str | None = Cookie(default=None)) -> dict[str, Any]:
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется вход")
    try:
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Сессия недействительна")

    user = store.state["users"].get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Пользователь не найден")
    return user


async def require_csrf(
    request: Request,
    csrf_cookie: str | None = Cookie(default=None, alias="csrf_token"),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> None:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Ошибка CSRF-проверки")


def find_user_by_email(email: str) -> dict[str, Any] | None:
    normalized = normalize_email(email)
    return next((u for u in store.state["users"].values() if u["email"] == normalized), None)


def accepted_friend_ids(user_id: str) -> set[str]:
    result: set[str] = set()
    for friendship in store.state["friendships"].values():
        if friendship["status"] != "accepted":
            continue
        if friendship["sender_id"] == user_id:
            result.add(friendship["receiver_id"])
        elif friendship["receiver_id"] == user_id:
            result.add(friendship["sender_id"])
    return result


def serialize_friendship(friendship: dict[str, Any], current_user_id: str) -> dict[str, Any]:
    other_id = (
        friendship["receiver_id"]
        if friendship["sender_id"] == current_user_id
        else friendship["sender_id"]
    )
    other = store.state["users"].get(other_id)
    return {
        "id": friendship["id"],
        "status": friendship["status"],
        "direction": "outgoing" if friendship["sender_id"] == current_user_id else "incoming",
        "created_at": friendship["created_at"],
        "friend": public_user(other) if other else None,
    }


app = FastAPI(title="Active Map Beta", version="0.2.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
async def startup() -> None:
    global http_client
    await store.load()
    http_client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0))
    if JWT_SECRET_EPHEMERAL:
        print("WARNING: JWT_SECRET сгенерирован временно. После перезапуска активные сессии завершатся.")


@app.on_event("shutdown")
async def shutdown() -> None:
    if http_client:
        await http_client.aclose()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(self)"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: blob: https://*.tile.openstreetmap.org https://unpkg.com; "
        "connect-src 'self'; "
        "font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    return response


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/register", status_code=201)
async def register(body: RegisterBody, response: Response) -> dict[str, Any]:
    email = normalize_email(str(body.email))
    async with store.lock:
        if find_user_by_email(email):
            raise HTTPException(status_code=409, detail="Пользователь с таким email уже существует")
        user_id = str(uuid.uuid4())
        user = {
            "id": user_id,
            "name": body.name,
            "email": email,
            "password_hash": password_hash.hash(body.password),
            "share_location": True,
            "created_at": utc_now_iso(),
        }
        store.state["users"][user_id] = user
        await store.save()

    set_auth_cookies(response, create_access_token(user_id))
    return {"user": public_user(user)}


@app.post("/api/auth/login")
async def login(body: LoginBody, response: Response, request: Request) -> dict[str, Any]:
    client_key = request.client.host if request.client else "unknown"
    now = time.time()
    recent_failures = [ts for ts in login_failures.get(client_key, []) if now - ts < 600]
    login_failures[client_key] = recent_failures
    if len(recent_failures) >= 5:
        raise HTTPException(status_code=429, detail="Слишком много неудачных попыток. Повторите позже")

    user = find_user_by_email(str(body.email))
    if not user or not password_hash.verify(body.password, user["password_hash"]):
        recent_failures.append(now)
        login_failures[client_key] = recent_failures
        raise HTTPException(status_code=401, detail="Неверный email или пароль")

    login_failures.pop(client_key, None)
    set_auth_cookies(response, create_access_token(user["id"]))
    return {"user": public_user(user)}


@app.post("/api/auth/logout", dependencies=[Depends(require_csrf)])
async def logout(response: Response) -> dict[str, bool]:
    clear_auth_cookies(response)
    return {"ok": True}


@app.get("/api/me")
async def me(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return {"user": public_user(current_user)}


@app.patch("/api/privacy", dependencies=[Depends(require_csrf)])
async def update_privacy(
    body: PrivacyBody,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    async with store.lock:
        current_user["share_location"] = body.share_location
        if not body.share_location:
            store.state["locations"].pop(current_user["id"], None)
        await store.save()
    return {"user": public_user(current_user)}


@app.put("/api/location", dependencies=[Depends(require_csrf)])
async def update_location(
    body: LocationBody,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    if not current_user.get("share_location", True):
        raise HTTPException(status_code=403, detail="Сначала включите передачу геолокации")
    location = {
        "lat": body.lat,
        "lng": body.lng,
        "accuracy": body.accuracy,
        "updated_at": utc_now_iso(),
        "updated_ts": time.time(),
    }
    async with store.lock:
        store.state["locations"][current_user["id"]] = location
        await store.save()
    return {"location": location}


@app.post("/api/friends/request", dependencies=[Depends(require_csrf)], status_code=201)
async def send_friend_request(
    body: FriendRequestBody,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    target = find_user_by_email(str(body.email))
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if target["id"] == current_user["id"]:
        raise HTTPException(status_code=400, detail="Нельзя добавить самого себя")

    async with store.lock:
        for friendship in store.state["friendships"].values():
            pair = {friendship["sender_id"], friendship["receiver_id"]}
            if pair == {current_user["id"], target["id"]}:
                raise HTTPException(status_code=409, detail="Заявка или дружба уже существует")

        friendship_id = str(uuid.uuid4())
        friendship = {
            "id": friendship_id,
            "sender_id": current_user["id"],
            "receiver_id": target["id"],
            "status": "pending",
            "created_at": utc_now_iso(),
        }
        store.state["friendships"][friendship_id] = friendship
        await store.save()
    return {"request": serialize_friendship(friendship, current_user["id"])}


@app.get("/api/friends")
async def list_friends(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    items = [
        serialize_friendship(item, current_user["id"])
        for item in store.state["friendships"].values()
        if current_user["id"] in {item["sender_id"], item["receiver_id"]}
    ]
    return {"items": items}


@app.post("/api/friends/{friendship_id}/accept", dependencies=[Depends(require_csrf)])
async def accept_friend_request(
    friendship_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    async with store.lock:
        friendship = store.state["friendships"].get(friendship_id)
        if not friendship:
            raise HTTPException(status_code=404, detail="Заявка не найдена")
        if friendship["receiver_id"] != current_user["id"]:
            raise HTTPException(status_code=403, detail="Эту заявку может принять только получатель")
        if friendship["status"] != "pending":
            raise HTTPException(status_code=409, detail="Заявка уже обработана")
        friendship["status"] = "accepted"
        friendship["accepted_at"] = utc_now_iso()
        await store.save()
    return {"request": serialize_friendship(friendship, current_user["id"])}


@app.delete("/api/friends/{friendship_id}", dependencies=[Depends(require_csrf)])
async def delete_friendship(
    friendship_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, bool]:
    async with store.lock:
        friendship = store.state["friendships"].get(friendship_id)
        if not friendship:
            raise HTTPException(status_code=404, detail="Связь не найдена")
        if current_user["id"] not in {friendship["sender_id"], friendship["receiver_id"]}:
            raise HTTPException(status_code=403, detail="Нет доступа")
        del store.state["friendships"][friendship_id]
        await store.save()
    return {"ok": True}


@app.get("/api/friends/locations")
async def friend_locations(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    result = []
    now = time.time()
    for friend_id in accepted_friend_ids(current_user["id"]):
        friend = store.state["users"].get(friend_id)
        location = store.state["locations"].get(friend_id)
        if not friend or not friend.get("share_location", True) or not location:
            continue
        age_seconds = max(0, int(now - float(location.get("updated_ts", now))))
        # Координаты старше часа не выдаём вообще.
        if age_seconds > 3600:
            continue
        result.append(
            {
                "user": public_user(friend),
                "location": {
                    "lat": location["lat"],
                    "lng": location["lng"],
                    "accuracy": location.get("accuracy"),
                    "updated_at": location["updated_at"],
                    "age_seconds": age_seconds,
                },
            }
        )
    return {"items": result}


def parse_bbox(raw: str) -> tuple[float, float, float, float]:
    try:
        south, west, north, east = [float(x) for x in raw.split(",")]
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="bbox должен иметь формат south,west,north,east")
    if not (-90 <= south < north <= 90 and -180 <= west < east <= 180):
        raise HTTPException(status_code=400, detail="Некорректные границы bbox")
    if (north - south) * (east - west) > MAX_BBOX_AREA:
        raise HTTPException(status_code=400, detail="Слишком большая область карты. Увеличьте масштаб")
    return south, west, north, east


@app.get("/api/map/objects")
async def map_objects(
    bbox: str = Query(..., description="south,west,north,east"),
) -> JSONResponse:
    south, west, north, east = parse_bbox(bbox)
    normalized_bbox = f"{south:.5f},{west:.5f},{north:.5f},{east:.5f}"
    cache_key = hashlib.sha256(normalized_bbox.encode()).hexdigest()
    cached = overpass_cache.get(cache_key)
    if cached and cached[0] > time.time():
        return JSONResponse(cached[1], headers={"X-Cache": "HIT"})

    query = f"""
    [out:json][timeout:25];
    (
      node[\"leisure\"=\"fitness_centre\"]({normalized_bbox});
      way[\"leisure\"=\"fitness_centre\"]({normalized_bbox});
      node[\"leisure\"=\"sports_centre\"]({normalized_bbox});
      way[\"leisure\"=\"sports_centre\"]({normalized_bbox});
      way[\"highway\"=\"cycleway\"]({normalized_bbox});
      way[\"cycleway\"]({normalized_bbox});
      node[\"amenity\"=\"bicycle_rental\"]({normalized_bbox});
      node[\"amenity\"=\"bicycle_parking\"]({normalized_bbox});
    );
    out geom;
    """
    assert http_client is not None
    try:
        response = await http_client.post(
            OVERPASS_URL,
            content=query.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
        )
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502, detail=f"Ошибка сервиса OpenStreetMap: {type(exc).__name__}")

    overpass_cache[cache_key] = (time.time() + OVERPASS_CACHE_SECONDS, data)
    if len(overpass_cache) > 200:
        expired = [key for key, value in overpass_cache.items() if value[0] <= time.time()]
        for key in expired:
            overpass_cache.pop(key, None)
    return JSONResponse(data, headers={"X-Cache": "MISS"})
