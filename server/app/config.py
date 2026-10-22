import os
from dotenv import load_dotenv

load_dotenv()

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "change-me-please")
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "30"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./rbxmanager.db")
