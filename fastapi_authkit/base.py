from typing import Optional
import fastapi
from .settings import SETTINGS
from .core.oauth import OAuth
from starlette.middleware.sessions import SessionMiddleware

SINGLETON = Optional


class OAuthApp:
    __instance: SINGLETON["OAuthApp"] = None

    def __init__(self, app: fastapi.FastAPI, secret_key: str) -> None:
        self.__app: fastapi.FastAPI = app
        self.__oauth: OAuth = OAuth()
        self.__instance = self
        self.app.add_middleware(
            SessionMiddleware,
            secret_key=secret_key,
        )

    def __new__(cls, app: fastapi.FastAPI, secret_key: str) -> "OAuthApp":
        if cls.__instance:
            return cls.__instance
        return super().__new__(cls)

    @property
    def app(self) -> fastapi.FastAPI:
        return self.__app

    @property
    def oauth(self) -> OAuth:
        return self.__oauth
