import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./rbxmanager.db")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "change-me-please")
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "30"))
