import os
import sys

# Ensure the app directory is in the python path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# Import the 'app' object from 'app.py' and name it 'application' for Passenger
from app import app as application
