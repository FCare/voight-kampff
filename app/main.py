#!/usr/bin/env python3
"""
Voight-Kampff - API Key Authentication Service with Web Interface
Inspired by Blade Runner's empathy test
"""

import os
import secrets
import re
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

from fastapi import FastAPI, Header, HTTPException, Depends, status, Request, Form, Cookie
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, DateTime, Boolean, Text, Integer, select, ForeignKey
import hashlib
import bcrypt
from itsdangerous import URLSafeTimedSerializer
import uvicorn

# Configuration
DB_PATH = os.getenv("VK_DB_PATH", "/data/voight-kampff.db")
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"
SECRET_KEY = os.getenv("VK_SECRET_KEY", secrets.token_urlsafe(32))
SESSION_EXPIRE_HOURS = int(os.getenv("VK_SESSION_EXPIRE_HOURS", "24"))

# Admin configuration
ADMIN_USERNAME = os.getenv("VK_ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("VK_ADMIN_PASSWORD")
ADMIN_EMAIL = os.getenv("VK_ADMIN_EMAIL", "admin@localhost")

# Security
session_serializer = URLSafeTimedSerializer(SECRET_KEY)

# Templates
templates = Jinja2Templates(directory="/app/templates")

# Service Configuration
class ServiceConfig:
    """Configuration centralisée des services"""
    
    # Services disponibles avec leurs métadonnées
    SERVICES = {
        "joshua-frontend": {
            "url": "https://assistant.caronboulme.fr",
            "display_name": "Joshua Assistant",
            "priority": 1
        },
        "thebrain": {
            "url": "https://thebrain.caronboulme.fr",
            "display_name": "The Brain",
            "priority": 2
        },
        "chatterbox": {
            "url": "https://chatterbox.caronboulme.fr",
            "display_name": "Chatterbox",
            "priority": 3
        },
        "unmute-talk": {
            "url": "https://unmute-talk.caronboulme.fr",
            "display_name": "Unmute Talk",
            "priority": 4
        },
        "unmute-transcript": {
            "url": "https://unmute-transcript.caronboulme.fr",
            "display_name": "Unmute Transcript",
            "priority": 5
        },
        "joshua-backend": {
            "url": "https://joshua.caronboulme.fr",
            "display_name": "Joshua API",
            "priority": 6
        }
    }
    
    @classmethod
    def get_default_scopes(cls) -> List[str]:
        """Retourne la liste des services par défaut pour un admin (scope '*')"""
        return list(cls.SERVICES.keys())
    
    @classmethod
    def get_service_priority(cls) -> List[Tuple[str, str]]:
        """Retourne la liste des services triés par priorité (nom, url)"""
        sorted_services = sorted(cls.SERVICES.items(), key=lambda x: x[1]["priority"])
        return [(name, data["url"]) for name, data in sorted_services]
    
    @classmethod
    def get_service_priority_with_names(cls) -> List[Tuple[str, str, str]]:
        """Retourne la liste des services triés par priorité (nom, url, display_name)"""
        sorted_services = sorted(cls.SERVICES.items(), key=lambda x: x[1]["priority"])
        return [(name, data["url"], data["display_name"]) for name, data in sorted_services]
    
    @classmethod
    def get_first_authorized_service(cls, user_scopes: List[str]) -> Tuple[Optional[str], Optional[str]]:
        """Retourne le premier service autorisé selon la priorité (url, display_name)"""
        for service_name, service_data in sorted(cls.SERVICES.items(), key=lambda x: x[1]["priority"]):
            if service_name in user_scopes:
                return service_data["url"], service_data["display_name"]
        return None, None

def parse_user_scopes(user) -> List[str]:
    """Parse les scopes d'un utilisateur en liste"""
    if user.allowed_scopes == "*":
        return ServiceConfig.get_default_scopes()
    elif user.allowed_scopes:
        return [s.strip() for s in user.allowed_scopes.split(',') if s.strip()]
    return []

# Database Models
class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    max_api_keys: Mapped[int] = mapped_column(Integer, default=100)  # Hardcoded to 100
    allowed_scopes: Mapped[str] = mapped_column(Text, default="")  # Allowed services for this user - NONE by default
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

class Session(Base):
    __tablename__ = "sessions"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    session_token: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_used: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    key_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    api_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))  # Reference to User.id
    user: Mapped[str] = mapped_column(String(255))  # Keep for backward compatibility
    scopes: Mapped[str] = mapped_column(Text)  # Comma-separated list of allowed services
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    

# Pydantic Models
class APIKeyCreate(BaseModel):
    key_name: str = Field(..., description="Unique name for this API key")
    user: str = Field(..., description="Username or identifier")
    scopes: List[str] = Field(..., description="List of allowed services (tts, stt, llm, assistant)")
    expires_in_days: Optional[int] = Field(None, description="Number of days until expiration (None = no expiration)")

class APIKeyResponse(BaseModel):
    id: int
    key_name: str
    api_key: str
    user: str
    scopes: List[str]
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime]
    expires_at: Optional[datetime]

class APIKeyList(BaseModel):
    id: int
    key_name: str
    user: str
    scopes: List[str]
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime]
    expires_at: Optional[datetime]

class VerifyResponse(BaseModel):
    valid: bool
    user: str
    service: str
    scopes: List[str]

# Database setup
engine = create_async_engine(DATABASE_URL, echo=False)
async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# Utility functions
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def create_session_token() -> str:
    return secrets.token_urlsafe(32)

def serialize_session(user_id: int) -> str:
    return session_serializer.dumps({"user_id": user_id})

def deserialize_session(token: str) -> Optional[int]:
    try:
        data = session_serializer.loads(token, max_age=SESSION_EXPIRE_HOURS * 3600)
        return data.get("user_id")
    except:
        return None

def validate_password(password: str) -> bool:
    """Validate password strength"""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True

async def get_current_user(request: Request, session_db: AsyncSession = Depends(get_session)) -> Optional[User]:
    """Get current user from session cookie"""
    session_cookie = request.cookies.get("vk_session")
    if not session_cookie:
        return None
    
    user_id = deserialize_session(session_cookie)
    if not user_id:
        return None
    
    # Get user from database
    result = await session_db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    return result.scalar_one_or_none()

# FastAPI app
app = FastAPI(
    title="Voight-Kampff",
    description="API Key Authentication Service - Testing for humanity, one request at a time",
    version="2.0.0"
)

async def create_admin_if_needed():
    """Create admin user if environment variables are set and no admin exists"""
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        return
    
    async with async_session_maker() as session:
        # Check if any admin user exists
        result = await session.execute(
            select(User).where(User.is_admin == True)
        )
        existing_admin = result.scalar_one_or_none()
        
        if existing_admin:
            print(f"Admin user already exists: {existing_admin.username}")
            return
        
        # Check if username already exists
        result = await session.execute(
            select(User).where(User.username == ADMIN_USERNAME)
        )
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            # Promote existing user to admin
            existing_user.is_admin = True
            existing_user.is_active = True
            existing_user.max_api_keys = 50  # Higher limit for admin
            await session.commit()
            print(f"Promoted existing user '{ADMIN_USERNAME}' to admin")
        else:
            # Create new admin user
            admin_user = User(
                username=ADMIN_USERNAME,
                email=ADMIN_EMAIL,
                hashed_password=hash_password(ADMIN_PASSWORD),
                is_active=True,
                is_admin=True,
                max_api_keys=100,  # Hardcoded limit
                allowed_scopes="*"  # Admin can access all services
            )
            session.add(admin_user)
            await session.commit()
            print(f"Created admin user: {ADMIN_USERNAME}")

@app.on_event("startup")
async def startup_event():
    await init_db()
    await create_admin_if_needed()
    print("🔍 Joshua authentication service is running")
    print(f"📁 Database: {DB_PATH}")
    print(f"🌐 Web interface available at /auth/")

@app.get("/")
async def root(request: Request, session_db: AsyncSession = Depends(get_session)):
    print(f"🔍 ROOT DEBUG - Root endpoint accessed from host: {request.headers.get('host')}")
    
    # Check if user is already logged in with valid session
    is_authenticated, user_name, db_key = await check_authentication(
        request, session_db, "auth", None, None
    )
    
    print(f"🔍 ROOT DEBUG - Authentication result: is_authenticated={is_authenticated}, user_name={user_name}")
    
    # Get the host to determine source domain
    host = request.headers.get('host', '')
    is_from_www = host.startswith('www.caronboulme.fr')
    
    print(f"🔍 ROOT DEBUG - Is from www.caronboulme.fr: {is_from_www}")
    
    if is_authenticated and user_name and user_name != "unknown":
        if is_from_www:
            # Only redirect to TheBrain if coming from www.caronboulme.fr
            thebrain_url = ServiceConfig.SERVICES["thebrain"]["url"]
            print(f"🔍 ROOT DEBUG - Redirecting to TheBrain from www")
            return RedirectResponse(url=f"{thebrain_url}/", status_code=302)
        else:
            # From auth.caronboulme.fr or other domains, redirect to dashboard
            print(f"🔍 ROOT DEBUG - Redirecting to dashboard from auth/other")
            return RedirectResponse(url="/auth/dashboard", status_code=302)
    
    # No valid session, redirect to login page
    print(f"🔍 ROOT DEBUG - Not authenticated, redirecting to login")
    return RedirectResponse(url="/auth/login", status_code=302)

@app.get("/health")
async def health():
    return {"status": "operational", "test": "positive"}

# ========== WEB AUTHENTICATION ENDPOINTS ==========

@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    redirect: Optional[str] = None,
    error: Optional[str] = None,
    pending_validation: Optional[str] = None
):
    """Login page"""
    success_message = None
    if pending_validation:
        success_message = "Inscription réussie ! Votre compte est en attente de validation par l'administrateur."
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "redirect_after": redirect,
        "error": error,
        "success": success_message
    })

@app.post("/auth/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    redirect_after: Optional[str] = Form(None),
    session_db: AsyncSession = Depends(get_session)
):
    """Process login form"""
    # Get user from database
    result = await session_db.execute(
        select(User).where(User.username == username)
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "redirect_after": redirect_after,
            "error": "Nom d'utilisateur ou mot de passe incorrect"
        })
    
    if not user.is_active:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "redirect_after": redirect_after,
            "error": "Votre compte est en attente de validation par l'administrateur"
        })
    
    # Update last login
    user.last_login = datetime.utcnow()
    await session_db.commit()
    
    # Create session
    session_token = serialize_session(user.id)
    
    # Prepare response - redirect to first authorized service or dashboard
    if redirect_after:
        response = RedirectResponse(url=redirect_after, status_code=303)
    else:
        # Find first authorized service for this user (refactored with ServiceConfig)
        user_scopes = parse_user_scopes(user)
        print(f"🔍 LOGIN DEBUG - User {user.username} scopes: {user_scopes}")
        
        # Get first authorized service according to priority
        redirect_url, service_name = ServiceConfig.get_first_authorized_service(user_scopes)
        
        if redirect_url:
            print(f"🔍 LOGIN DEBUG - Redirecting {user.username} to {service_name}: {redirect_url}")
        else:
            # No authorized services found, fallback to dashboard
            redirect_url = "/auth/dashboard"
            print(f"🔍 LOGIN DEBUG - No authorized services for {user.username}, redirecting to dashboard")
        
        response = RedirectResponse(url=redirect_url, status_code=303)
    
    # Set session cookie
    response.set_cookie(
        key="vk_session",
        value=session_token,
        max_age=SESSION_EXPIRE_HOURS * 3600,
        httponly=True,
        secure=True,
        samesite="lax",
        domain=".caronboulme.fr"  # Allow cookie on all subdomains
    )
    
    return response

@app.get("/auth/register", response_class=HTMLResponse)
async def register_page(request: Request, redirect: Optional[str] = None, error: Optional[str] = None):
    """Registration page"""
    return templates.TemplateResponse("register.html", {
        "request": request,
        "redirect_after": redirect,
        "error": error
    })

@app.post("/auth/register")
async def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    redirect_after: Optional[str] = Form(None),
    session_db: AsyncSession = Depends(get_session)
):
    """Process registration form"""
    
    # Validation
    if password != password_confirm:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "redirect_after": redirect_after,
            "error": "Les mots de passe ne correspondent pas"
        })
    
    if not validate_password(password):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "redirect_after": redirect_after,
            "error": "Le mot de passe ne respecte pas les exigences de sécurité"
        })
    
    # Check if user exists
    result = await session_db.execute(
        select(User).where(
            (User.username == username) | (User.email == email)
        )
    )
    if result.scalar_one_or_none():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "redirect_after": redirect_after,
            "error": "Ce nom d'utilisateur ou email est déjà utilisé"
        })
    
    # Create user (inactive until admin validation)
    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password)
        # is_active defaults to False now
    )
    session_db.add(user)
    await session_db.commit()
    await session_db.refresh(user)
    
    # Redirect to login with pending validation message
    return RedirectResponse(
        url="/auth/login?pending_validation=true",
        status_code=303
    )

@app.get("/auth/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session),
    success: Optional[str] = None,
    error: Optional[str] = None
):
    """Dashboard page"""
    if not current_user:
        return RedirectResponse(url=f"/auth/login?redirect={request.url}", status_code=303)
    
    # Get user's API keys
    result = await session_db.execute(
        select(APIKey).where(APIKey.user_id == current_user.id).order_by(APIKey.created_at.desc())
    )
    api_keys = result.scalars().all()
    
    # Format API keys for display
    api_keys_formatted = []
    for key in api_keys:
        api_keys_formatted.append({
            'id': key.id,
            'key_name': key.key_name,
            'api_key': key.api_key,
            'scopes': [s.strip() for s in key.scopes.split(',')],
            'is_active': key.is_active,
            'created_at': key.created_at,
            'last_used': key.last_used,
            'expires_at': key.expires_at
        })
    
    # Admin data if user is admin
    admin_users = []
    if current_user.is_admin:
        result = await session_db.execute(
            select(User).order_by(User.created_at.desc())
        )
        all_users = result.scalars().all()
        
        for user in all_users:
            # Get detailed API keys for each user
            api_key_result = await session_db.execute(
                select(APIKey).where(APIKey.user_id == user.id)
            )
            user_api_keys = api_key_result.scalars().all()
            
            # Format API keys for admin display
            formatted_api_keys = []
            for key in user_api_keys:
                formatted_api_keys.append({
                    'id': key.id,
                    'key_name': key.key_name,
                    'api_key': key.api_key,
                    'scopes': [s.strip() for s in key.scopes.split(',')],
                    'is_active': key.is_active,
                    'created_at': key.created_at,
                    'last_used': key.last_used,
                    'expires_at': key.expires_at
                })
            
            admin_users.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'is_admin': user.is_admin,
                'max_api_keys': user.max_api_keys,
                'allowed_scopes': user.allowed_scopes,
                'api_key_count': len(user_api_keys),
                'api_keys': formatted_api_keys,
                'created_at': user.created_at,
                'last_login': user.last_login
            })
    
    # Parse user's allowed scopes for the API key creation form (refactored with ServiceConfig)
    user_allowed_scopes = parse_user_scopes(current_user)
    
    # Get all available services sorted by priority for dynamic template
    available_services = []
    for service_name, service_data in sorted(ServiceConfig.SERVICES.items(), key=lambda x: x[1]["priority"]):
        available_services.append({
            'name': service_name,
            'display_name': service_data['display_name'],
            'priority': service_data['priority']
        })
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user.username,
        "is_admin": current_user.is_admin,
        "max_api_keys": current_user.max_api_keys,
        "api_key_count": len(api_keys),
        "api_keys": api_keys_formatted,
        "admin_users": admin_users,
        "user_allowed_scopes": user_allowed_scopes,
        "available_services": available_services,
        "success": success,
        "error": error
    })

@app.get("/auth/admin/traefik")
async def admin_traefik_dashboard(
    current_user: User = Depends(get_current_user)
):
    """Redirect admin to Traefik dashboard"""
    if not current_user or not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Redirect to secured Traefik dashboard
    return RedirectResponse(url="https://traefik.caronboulme.fr", status_code=302)

@app.post("/auth/dashboard/create-key")
async def create_key_web(
    request: Request,
    key_name: str = Form(...),
    scopes: List[str] = Form(...),
    expires_in_days: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Create API key from web interface"""
    if not current_user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    try:
        # Check if key_name already exists for this user
        result = await session_db.execute(
            select(APIKey).where(APIKey.key_name == key_name, APIKey.user_id == current_user.id)
        )
        if result.scalar_one_or_none():
            return RedirectResponse(
                url=f"/auth/dashboard?error=Une clé avec ce nom existe déjà",
                status_code=303
            )
        
        # Check allowed scopes for this user
        user_allowed_scopes = [s.strip() for s in current_user.allowed_scopes.split(',')]
        requested_scopes = set(scopes)
        
        # If user doesn't have "*" (all services), check individual scopes
        if "*" not in user_allowed_scopes:
            forbidden_scopes = requested_scopes - set(user_allowed_scopes)
            if forbidden_scopes:
                return RedirectResponse(
                    url=f"/auth/dashboard?error=Services non autorisés: {', '.join(forbidden_scopes)}. Contactez l'administrateur.",
                    status_code=303
                )
        
        # Generate secure API key
        new_api_key = secrets.token_urlsafe(48)
        
        # Calculate expiration
        expires_at = None
        if expires_in_days and expires_in_days.strip():
            expires_at = datetime.utcnow() + timedelta(days=int(expires_in_days))
        
        # Create new key
        db_key = APIKey(
            key_name=key_name,
            api_key=new_api_key,
            user_id=current_user.id,
            user=current_user.username,  # For backward compatibility
            scopes=','.join(scopes),
            expires_at=expires_at
        )
        
        session_db.add(db_key)
        await session_db.commit()
        
        return RedirectResponse(
            url=f"/auth/dashboard?success=Clé API créée avec succès: {key_name}",
            status_code=303
        )
        
    except Exception as e:
        return RedirectResponse(
            url=f"/auth/dashboard?error=Erreur lors de la création de la clé: {str(e)}",
            status_code=303
        )

@app.post("/auth/dashboard/toggle-key/{key_id}")
async def toggle_key_web(
    key_id: int,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Toggle API key status from web interface"""
    if not current_user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    result = await session_db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == current_user.id)
    )
    db_key = result.scalar_one_or_none()
    
    if not db_key:
        return RedirectResponse(
            url=f"/auth/dashboard?error=Clé API introuvable",
            status_code=303
        )
    
    db_key.is_active = not db_key.is_active
    await session_db.commit()
    
    status_text = "activée" if db_key.is_active else "désactivée"
    return RedirectResponse(
        url=f"/auth/dashboard?success=Clé API {status_text} avec succès",
        status_code=303
    )

@app.post("/auth/dashboard/delete-key/{key_id}")
async def delete_key_web(
    key_id: int,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Delete API key from web interface"""
    if not current_user:
        return RedirectResponse(url="/auth/login", status_code=303)
    
    result = await session_db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == current_user.id)
    )
    db_key = result.scalar_one_or_none()
    
    if not db_key:
        return RedirectResponse(
            url=f"/auth/dashboard?error=Clé API introuvable",
            status_code=303
        )
    
    await session_db.delete(db_key)
    await session_db.commit()
    
    return RedirectResponse(
        url=f"/auth/dashboard?success=Clé API supprimée avec succès",
        status_code=303
    )

@app.get("/auth/logout")
async def logout():
    """Logout and clear session"""
    print(f"🔍 LOGOUT DEBUG - User logged out")
    response = RedirectResponse(url="/auth/login", status_code=303)
    
    # Delete cookie with same domain settings as when it was created
    response.delete_cookie(
        key="vk_session",
        domain=".caronboulme.fr",  # Same domain as when cookie was set
        secure=True,
        samesite="lax"
    )
    print(f"🔍 LOGOUT DEBUG - Session cookie deleted for domain .caronboulme.fr")
    return response

# ========== ADMIN ENDPOINTS ==========

@app.post("/auth/admin/activate-user/{user_id}")
async def activate_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Activate a user account (admin only)"""
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Accès interdit", status_code=303)
    
    result = await session_db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        return RedirectResponse(url="/auth/dashboard?error=Utilisateur introuvable", status_code=303)
    
    user.is_active = True
    await session_db.commit()
    
    return RedirectResponse(
        url=f"/auth/dashboard?success=Utilisateur {user.username} activé avec succès",
        status_code=303
    )

@app.post("/auth/admin/deactivate-user/{user_id}")
async def deactivate_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Deactivate a user account (admin only)"""
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Accès interdit", status_code=303)
    
    result = await session_db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        return RedirectResponse(url="/auth/dashboard?error=Utilisateur introuvable", status_code=303)
    
    if user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Impossible de désactiver un administrateur", status_code=303)
    
    user.is_active = False
    await session_db.commit()
    
    return RedirectResponse(
        url=f"/auth/dashboard?success=Utilisateur {user.username} désactivé",
        status_code=303
    )

@app.post("/auth/admin/set-api-limit/{user_id}")
async def set_user_api_limit(
    user_id: int,
    max_keys: int = Form(...),
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Set API key limit for a user (admin only)"""
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Accès interdit", status_code=303)
    
    result = await session_db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        return RedirectResponse(url="/auth/dashboard?error=Utilisateur introuvable", status_code=303)
    
    if max_keys < 0 or max_keys > 100:
        return RedirectResponse(url="/auth/dashboard?error=Limite invalide (0-100)", status_code=303)
    
    user.max_api_keys = max_keys
    await session_db.commit()
    
    return RedirectResponse(
        url=f"/auth/dashboard?success=Limite API pour {user.username} définie à {max_keys}",
        status_code=303
    )

@app.post("/auth/admin/delete-user/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Delete a user account permanently (admin only)"""
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Accès interdit", status_code=303)
    
    result = await session_db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        return RedirectResponse(url="/auth/dashboard?error=Utilisateur introuvable", status_code=303)
    
    if user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Impossible de supprimer un administrateur", status_code=303)
    
    if user.id == current_user.id:
        return RedirectResponse(url="/auth/dashboard?error=Impossible de se supprimer soi-même", status_code=303)
    
    # Delete all user's API keys first
    await session_db.execute(
        select(APIKey).where(APIKey.user_id == user_id)
    )
    user_keys = (await session_db.execute(
        select(APIKey).where(APIKey.user_id == user_id)
    )).scalars().all()
    
    for key in user_keys:
        await session_db.delete(key)
    
    # Delete the user
    username = user.username
    await session_db.delete(user)
    await session_db.commit()
    
    return RedirectResponse(
        url=f"/auth/dashboard?success=Utilisateur {username} supprimé définitivement",
        status_code=303
    )

@app.post("/auth/admin/set-user-scopes/{user_id}")
async def set_user_scopes(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Set allowed services/scopes for a user (admin only)"""
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Accès interdit", status_code=303)
    
    # Récupérer les données du formulaire
    form_data = await request.form()
    services = form_data.getlist("service")  # Récupère toutes les valeurs cochées
    
    # Si aucun service sélectionné, définir comme vide
    if not services:
        new_scopes = ""
    else:
        # Si "*" (tous services) est sélectionné, on utilise "*"
        if "*" in services:
            new_scopes = "*"
        else:
            # Sinon, joindre les services sélectionnés par des virgules
            new_scopes = ",".join(services)
    
    result = await session_db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        return RedirectResponse(url="/auth/dashboard?error=Utilisateur introuvable", status_code=303)
    
    user.allowed_scopes = new_scopes
    await session_db.commit()
    
    scope_display = "Tous les services" if new_scopes == "*" else (new_scopes or "Aucun service")
    return RedirectResponse(
        url=f"/auth/dashboard?success=Services autorisés mis à jour pour {user.username}: {scope_display}",
        status_code=303
    )

@app.post("/auth/admin/revoke-user-key/{key_id}")
async def revoke_user_key(
    key_id: int,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Revoke (delete) a user's API key (admin only)"""
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Accès interdit", status_code=303)
    
    result = await session_db.execute(
        select(APIKey).where(APIKey.id == key_id)
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        return RedirectResponse(url="/auth/dashboard?error=Clé API introuvable", status_code=303)
    
    key_name = api_key.key_name
    user_name = api_key.user
    await session_db.delete(api_key)
    await session_db.commit()
    
    return RedirectResponse(
        url=f"/auth/dashboard?success=Clé '{key_name}' de {user_name} révoquée",
        status_code=303
    )

@app.post("/auth/admin/toggle-admin/{user_id}")
async def toggle_admin_status(
    user_id: int,
    current_user: User = Depends(get_current_user),
    session_db: AsyncSession = Depends(get_session)
):
    """Toggle admin status of a user (admin only)"""
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/auth/dashboard?error=Accès interdit", status_code=303)
    
    # Get target user
    result = await session_db.execute(
        select(User).where(User.id == user_id)
    )
    target_user = result.scalar_one_or_none()
    
    if not target_user:
        return RedirectResponse(url="/auth/dashboard?error=Utilisateur introuvable", status_code=303)
    
    # Prevent self-demotion to avoid lock-out
    if target_user.id == current_user.id:
        return RedirectResponse(url="/auth/dashboard?error=Vous ne pouvez pas modifier votre propre statut admin", status_code=303)
    
    # Toggle admin status
    new_status = not target_user.is_admin
    target_user.is_admin = new_status
    await session_db.commit()
    
    status_text = "promu admin" if new_status else "rétrogradé utilisateur"
    return RedirectResponse(
        url=f"/auth/dashboard?success=Utilisateur {target_user.username} {status_text}",
        status_code=303
    )

# ========== AUTHENTICATION HELPER FUNCTION ==========

async def check_authentication(
    request: Request,
    session: AsyncSession,
    service: str = "unknown",
    authorization: Optional[str] = None,
    x_api_key: Optional[str] = None
) -> tuple[bool, Optional[str], Optional[APIKey]]:
    """
    Common authentication logic for both /verify and landing page
    Returns: (is_authenticated, username, api_key_record)
    """
    
    print(f"🔍 AUTH DEBUG - Starting check_authentication for service: {service}")
    
    api_key = None
    user_name = "unknown"
    
    # Method 1: Try Authorization header (Bearer token)
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization.replace("Bearer ", "").strip()
        print(f"🔍 AUTH DEBUG - Using Bearer token")
    
    # Method 2: Try X-API-Key header
    elif x_api_key:
        api_key = x_api_key.strip()
        print(f"🔍 AUTH DEBUG - Using X-API-Key header")
    
    # Method 3: Try session cookie
    elif request.cookies.get("vk_session"):
        session_cookie = request.cookies.get("vk_session")
        print(f"🔍 AUTH DEBUG - Found session cookie, deserializing...")
        user_id = deserialize_session(session_cookie)
        print(f"🔍 AUTH DEBUG - Deserialized user_id: {user_id}")
        
        if user_id:
            # Get user from database
            user_result = await session.execute(
                select(User).where(User.id == user_id, User.is_active == True)
            )
            user = user_result.scalar_one_or_none()
            print(f"🔍 AUTH DEBUG - User query result: {user.username if user else 'None'}")
            
            if user:
                user_name = user.username
                print(f"🔍 AUTH DEBUG - User found: {user_name}, allowed_scopes: {user.allowed_scopes}, is_admin: {user.is_admin}")
                
                # For session cookies, verify USER scopes (admin-controlled permissions)
                if user.allowed_scopes is None or user.allowed_scopes.strip() == "":
                    # No scopes defined, deny access (except auth service)
                    user_allowed_scopes = []
                    print(f"🔍 AUTH DEBUG - No scopes defined for user")
                else:
                    user_allowed_scopes = [s.strip() for s in user.allowed_scopes.split(',') if s.strip()]
                    print(f"🔍 AUTH DEBUG - User allowed scopes: {user_allowed_scopes}")
                
                # Admin users automatically get traefik access
                if user.is_admin and 'traefik' not in user_allowed_scopes:
                    user_allowed_scopes.append('traefik')
                    print(f"🔍 AUTH DEBUG - Admin user: automatically added traefik access")
                
                # Special case: always allow access to auth service for session management
                if service == "auth":
                    api_key = f"session_{user_id}_{service}"
                    print(f"🔍 AUTH DEBUG - Allowing auth service access")
                elif service == "*":
                    # Landing page or general access check - allow if user has any scopes or is admin
                    if user.allowed_scopes == "*" or user.allowed_scopes.strip() != "" or user.is_admin:
                        api_key = f"session_{user_id}_{service}"
                        print(f"🔍 AUTH DEBUG - Allowing general access (*) - user has scopes: {user.allowed_scopes}")
                    else:
                        print(f"🔍 AUTH DEBUG - User {user_name} has no scopes for general access")
                        return False, None, None
                elif user.allowed_scopes == "*" or '*' in user_allowed_scopes or service in user_allowed_scopes:
                    # User has permission for this specific service
                    api_key = f"session_{user_id}_{service}"
                    print(f"🔍 AUTH DEBUG - User has permission for service {service}")
                else:
                    # User doesn't have permission for this service
                    print(f"🔍 AUTH DEBUG - User {user_name} does NOT have permission for service {service}")
                    return False, None, None
            else:
                print(f"🔍 AUTH DEBUG - No active user found for user_id {user_id}")
        else:
            print(f"🔍 AUTH DEBUG - Failed to deserialize session cookie")
    else:
        print(f"🔍 AUTH DEBUG - No authentication method found")
    
    # If no authentication method found
    if not api_key:
        print(f"🔍 AUTH DEBUG - No API key generated, authentication failed")
        return False, None, None
    
    print(f"🔍 AUTH DEBUG - API key generated: {api_key[:20]}...")
    
    # Handle session-based authentication (pseudo API keys)
    if api_key.startswith("session_"):
        # For session-based auth, we already validated the user and scopes above
        # Return success with the user_name we extracted from session
        return True, user_name, None
    
    # Query database for real API key
    result = await session.execute(
        select(APIKey).where(APIKey.api_key == api_key)
    )
    db_key = result.scalar_one_or_none()
    
    if not db_key:
        return False, None, None
    
    # Check if key is active
    if not db_key.is_active:
        return False, None, None
    
    # Check expiration
    if db_key.expires_at and db_key.expires_at < datetime.utcnow():
        return False, None, None
    
    # Check scopes for real API keys
    allowed_scopes = [s.strip() for s in db_key.scopes.split(',')]
    if service not in allowed_scopes and '*' not in allowed_scopes:
        return False, None, None
    
    # Update last_used timestamp for real API keys
    db_key.last_used = datetime.utcnow()
    await session.commit()
    
    # Use the original user name if available, otherwise fall back to API key user
    final_user = user_name if user_name != "unknown" else db_key.user
    
    return True, final_user, db_key

# ========== VERIFICATION ENDPOINT (ENHANCED FOR COOKIES) ==========

@app.get("/verify")
async def verify_api_key(
    request: Request,
    x_forwarded_uri: Optional[str] = Header(None),
    x_forwarded_host: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
    session_db: AsyncSession = Depends(get_session)
):
    """
    Enhanced verify endpoint for Traefik ForwardAuth
    Supports both API keys and session cookies
    """
    
    # Extract service name from forwarded host
    service = "unknown"
    if x_forwarded_host:
        service = x_forwarded_host.split('.')[0]
    
    # Debug logging
    print(f"🔍 VERIFY DEBUG - Service: {service}")
    print(f"🔍 VERIFY DEBUG - X-Forwarded-Host: {x_forwarded_host}")
    print(f"🔍 VERIFY DEBUG - X-Forwarded-Uri: {x_forwarded_uri}")
    print(f"🔍 VERIFY DEBUG - Authorization header: {'Bearer ***' if authorization and authorization.startswith('Bearer') else authorization}")
    print(f"🔍 VERIFY DEBUG - X-API-Key header: {'***' if x_api_key else None}")
    print(f"🔍 VERIFY DEBUG - Session cookie: {'present' if request.cookies.get('vk_session') else 'absent'}")
    
    # Special case: Allow unrestricted access to photos/immich (has its own auth)
    if service == "photos":
        print(f"🔍 VERIFY DEBUG - Photos service bypass")
        return JSONResponse(
            status_code=200,
            content={"valid": True, "user": "immich-bypass", "service": service},
            headers={
                "X-VK-User": "immich-bypass",
                "X-VK-Service": service
            }
        )
    
    # Check authentication using common function for other services
    print(f"🔍 VERIFY DEBUG - Calling check_authentication for service: {service}")
    is_authenticated, user_name, db_key = await check_authentication(
        request, session_db, service, authorization, x_api_key
    )
    
    print(f"🔍 VERIFY DEBUG - Authentication result: is_authenticated={is_authenticated}, user_name={user_name}, db_key={'present' if db_key else 'None'}")
    
    if not is_authenticated:
        print(f"🔍 VERIFY DEBUG - Authentication FAILED for service {service}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication"
        )
    
    # Check if admin access is required for specific services
    if service == "traefik":
        # Get user from database to check admin status
        result = await session_db.execute(
            select(User).where(User.username == user_name)
        )
        user = result.scalar_one_or_none()
        
        if not user or not user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
    
    # Return success with custom headers
    # Handle session cookies where db_key is None
    scopes = db_key.scopes if db_key else "session"
    
    return JSONResponse(
        status_code=200,
        content={"valid": True, "user": user_name, "service": service},
        headers={
            "X-VK-User": user_name,
            "X-VK-Service": service,
            "X-VK-Scopes": scopes
        }
    )


# ========== LANDING PAGE WITH CONDITIONAL REDIRECT ==========

@app.get("/landing", response_class=HTMLResponse)
async def landing_page(
    request: Request,
    session_db: AsyncSession = Depends(get_session)
):
    """
    Landing page that redirects based on authentication status and source domain
    - From www.caronboulme.fr + authenticated: Redirect to thebrain.caronboulme.fr
    - From auth.caronboulme.fr + authenticated: Redirect to dashboard
    - Not authenticated: Redirect to auth.caronboulme.fr/auth/login
    """
    
    print(f"🔍 LANDING DEBUG - Starting landing page authentication check")
    print(f"🔍 LANDING DEBUG - Session cookie present: {'yes' if request.cookies.get('vk_session') else 'no'}")
    print(f"🔍 LANDING DEBUG - Host header: {request.headers.get('host')}")
    
    # Check authentication (no specific service required for landing)
    is_authenticated, user_name, _ = await check_authentication(
        request, session_db, "*"
    )
    
    print(f"🔍 LANDING DEBUG - Authentication result: is_authenticated={is_authenticated}, user_name={user_name}")
    
    # Get the host to determine source domain
    host = request.headers.get('host', '')
    is_from_www = host.startswith('www.caronboulme.fr')
    print(f"🔍 LANDING DEBUG - Is from www.caronboulme.fr: {is_from_www}")
    
    if is_authenticated:
        if is_from_www:
            # Get user from database to check their allowed scopes
            session_cookie = request.cookies.get("vk_session")
            user_id = deserialize_session(session_cookie) if session_cookie else None
            
            if user_id:
                user_result = await session_db.execute(
                    select(User).where(User.id == user_id, User.is_active == True)
                )
                user = user_result.scalar_one_or_none()
                
                if user:
                    user_scopes = parse_user_scopes(user)
                    print(f"🔍 LANDING DEBUG - User scopes: {user_scopes}")
                    
                    # Get first authorized service according to priority (refactored with ServiceConfig)
                    redirect_url, display_name = ServiceConfig.get_first_authorized_service(user_scopes)
                    
                    if redirect_url:
                        title = f"Welcome back, {user_name}!"
                        message = f"Hello {user_name}, redirecting you to {display_name}..."
                        print(f"🔍 LANDING DEBUG - Redirecting to {display_name}: {redirect_url}")
                    else:
                        # No authorized services found, redirect to dashboard
                        redirect_url = "https://auth.caronboulme.fr/auth/dashboard"
                        title = f"Welcome back, {user_name}!"
                        message = f"Hello {user_name}, no authorized services found. Redirecting to dashboard..."
                        print(f"🔍 LANDING DEBUG - No authorized services, redirecting to dashboard")
                else:
                    # User not found, redirect to login
                    redirect_url = "https://auth.caronboulme.fr/auth/login"
                    title = "Authentication Required"
                    message = "Please login to access your services..."
            else:
                # No valid session, redirect to login
                redirect_url = "https://auth.caronboulme.fr/auth/login"
                title = "Authentication Required"
                message = "Please login to access your services..."
        else:
            # From auth.caronboulme.fr or other domains, show landing page without redirect
            redirect_url = None  # No automatic redirect
            title = f"Welcome back, {user_name}!"
            message = f"Hello {user_name}, you are successfully authenticated!"
    else:
        redirect_url = "https://auth.caronboulme.fr/auth/login"
        title = "Authentication Required"
        message = "Please login to access your services..."
    
    # Generate different HTML based on whether we have a redirect_url
    if redirect_url:
        html_content = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
            <meta http-equiv="refresh" content="2;url={redirect_url}">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                    color: #fff;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0;
                }}
                .container {{
                    text-align: center;
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }}
                .logo {{
                    font-size: 3em;
                    margin-bottom: 20px;
                }}
                .spinner {{
                    border: 3px solid rgba(255, 255, 255, 0.3);
                    border-top: 3px solid #4ecdc4;
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
                a {{
                    color: #4ecdc4;
                    text-decoration: none;
                    font-weight: 500;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🔍</div>
                <h1>{title}</h1>
                <p>{message}</p>
                <div class="spinner"></div>
                <p><a href="{redirect_url}">Click here if you are not redirected automatically</a></p>
            </div>
            <script>
                setTimeout(function() {{
                    window.location.href = "{redirect_url}";
                }}, 2000);
            </script>
        </body>
        </html>
        """
    else:
        # No redirect - show static landing page
        html_content = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                    color: #fff;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0;
                }}
                .container {{
                    text-align: center;
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    max-width: 500px;
                }}
                .logo {{
                    font-size: 3em;
                    margin-bottom: 20px;
                }}
                .services {{
                    margin-top: 30px;
                }}
                .service-link {{
                    display: inline-block;
                    background: rgba(78, 205, 196, 0.2);
                    color: #4ecdc4;
                    padding: 10px 20px;
                    margin: 10px;
                    border-radius: 10px;
                    text-decoration: none;
                    font-weight: 500;
                    border: 1px solid rgba(78, 205, 196, 0.3);
                    transition: all 0.3s ease;
                }}
                .service-link:hover {{
                    background: rgba(78, 205, 196, 0.3);
                    transform: translateY(-2px);
                }}
                .dashboard-link {{
                    background: rgba(255, 255, 255, 0.2);
                    color: #fff;
                    margin-top: 20px;
                }}
                .dashboard-link:hover {{
                    background: rgba(255, 255, 255, 0.3);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🔍</div>
                <h1>{title}</h1>
                <p>{message}</p>
                
                <div class="services">
                    <h3>Available Services</h3>
                    <a href="{ServiceConfig.SERVICES["joshua-frontend"]["url"]}" class="service-link">🤖 Joshua Assistant</a>
                    <a href="{ServiceConfig.SERVICES["thebrain"]["url"]}" class="service-link">🧠 The Brain</a>
                    <a href="{ServiceConfig.SERVICES["chatterbox"]["url"]}" class="service-link">💬 Chatterbox</a>
                    <a href="{ServiceConfig.SERVICES["unmute-talk"]["url"]}" class="service-link">🎤 Unmute Talk</a>
                    <a href="{ServiceConfig.SERVICES["unmute-transcript"]["url"]}" class="service-link">📝 Unmute Transcript</a>
                    <a href="{ServiceConfig.SERVICES["joshua-backend"]["url"]}" class="service-link">🔧 Joshua API</a>
                    <a href="https://photos.caronboulme.fr" class="service-link">📸 Photos</a>
                    
                    <br>
                    <a href="/auth/dashboard" class="service-link dashboard-link">⚙️ Account Dashboard</a>
                </div>
            </div>
        </body>
        </html>
        """
    
    return HTMLResponse(content=html_content, status_code=200)

# ========== ORIGINAL API ENDPOINTS ==========

@app.post("/keys", response_model=APIKeyResponse)
async def create_api_key(
    key_data: APIKeyCreate,
    session: AsyncSession = Depends(get_session)
):
    """
    Create a new API key (original API endpoint)
    """
    
    # Check if key_name already exists
    result = await session.execute(
        select(APIKey).where(APIKey.key_name == key_data.key_name)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An API key with this name already exists"
        )
    
    # Generate secure API key
    new_api_key = secrets.token_urlsafe(48)
    
    # Calculate expiration
    expires_at = None
    if key_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)
    
    # Create new key
    db_key = APIKey(
        key_name=key_data.key_name,
        api_key=new_api_key,
        user_id=0,  # For API-created keys, use 0 as default user_id
        user=key_data.user,
        scopes=','.join(key_data.scopes),
        expires_at=expires_at
    )
    
    session.add(db_key)
    await session.commit()
    await session.refresh(db_key)
    
    return APIKeyResponse(
        id=db_key.id,
        key_name=db_key.key_name,
        api_key=db_key.api_key,
        user=db_key.user,
        scopes=key_data.scopes,
        is_active=db_key.is_active,
        created_at=db_key.created_at,
        last_used=db_key.last_used,
        expires_at=db_key.expires_at
    )

@app.get("/keys", response_model=List[APIKeyList])
async def list_api_keys(
    session: AsyncSession = Depends(get_session)
):
    """
    List all API keys (without exposing the actual keys)
    """
    result = await session.execute(select(APIKey))
    keys = result.scalars().all()
    
    return [
        APIKeyList(
            id=key.id,
            key_name=key.key_name,
            user=key.user,
            scopes=[s.strip() for s in key.scopes.split(',')],
            is_active=key.is_active,
            created_at=key.created_at,
            last_used=key.last_used,
            expires_at=key.expires_at
        )
        for key in keys
    ]

@app.delete("/keys/{key_id}")
async def delete_api_key(
    key_id: int,
    session: AsyncSession = Depends(get_session)
):
    """
    Delete an API key
    """
    result = await session.execute(
        select(APIKey).where(APIKey.id == key_id)
    )
    db_key = result.scalar_one_or_none()
    
    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    await session.delete(db_key)
    await session.commit()
    
    return {"message": "API key deleted successfully"}

@app.patch("/keys/{key_id}/toggle")
async def toggle_api_key(
    key_id: int,
    session: AsyncSession = Depends(get_session)
):
    """
    Enable or disable an API key
    """
    result = await session.execute(
        select(APIKey).where(APIKey.id == key_id)
    )
    db_key = result.scalar_one_or_none()
    
    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    db_key.is_active = not db_key.is_active
    await session.commit()
    
    return {
        "message": f"API key {'enabled' if db_key.is_active else 'disabled'}",
        "is_active": db_key.is_active
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level="info"
    )
