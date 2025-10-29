# This file makes the project a Python package
from .app import create_app, create_tables

__all__ = ['create_app', 'create_tables']