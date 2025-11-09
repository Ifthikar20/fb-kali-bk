"""FetchBot.ai - Application Entry Point"""
import sys
import os

# Add parent directory to path to allow importing from parent modules
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import the FastAPI app from the api module
from api import app

__all__ = ['app']
