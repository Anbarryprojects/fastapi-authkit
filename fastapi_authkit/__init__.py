from .base import OAuthApp
from .settings import SETTINGS as AuthSetting
from .core import providers as AuthProviders

__version__ = "0.0.1"
__author__ = "papuridalego@gmail.com"
__all__ = ["OAuthApp", "AuthSetting", "AuthProviders"]
