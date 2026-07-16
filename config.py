import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SECRET_KEY = os.environ.get("RAVN_SECRET_KEY", "ravn-ai-dev-secret-change-in-production")
DATABASE = os.path.join(BASE_DIR, "data", "ravn.db")
