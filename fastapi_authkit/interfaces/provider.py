import abc
import typing
import pydantic
import fastapi

from ..settings import SETTINGS

from ..core.oauth import OAuth
from ..core.oauth import UserInfoModel
from ..core.oauth import AuthVia
from ..core.oauth import Url

from .. import OAuthApp

from .logics import IAuthLogic


class TokenResponse(pydantic.BaseModel):
    access_token: str
    token_type: str


class AuthenticationMethod(abc.ABC):
    router: fastapi.APIRouter

    def __init__(
        self,
        name: str,
        router: fastapi.APIRouter,
        oauth_app: OAuthApp,
        auth_vias: AuthVia,
        auth_logic: IAuthLogic,
    ) -> None:
        self.router = router
        self.auth_logic: IAuthLogic = auth_logic
        self.settings: SETTINGS = SETTINGS(**auth_vias.get_setting(name=name))
        self.configure()
        auth_vias.register(self.settings.dict())
        self.oauth_app: OAuthApp = oauth_app
        self.oauth_provider: OAuth = oauth_app.oauth
        self.auth_vias: AuthVia = auth_vias
        self.name: str = name
        self.authenticator: AuthVia.Authenticator = self.auth_vias(
            self.name,
            self.get_urls(),
        )
        self.routes()
        self.oauth_app.app.include_router(self.router)

    @abc.abstractmethod
    def configure(self):
        ...

    @abc.abstractmethod
    def create_userinfo(self, userinfo: dict[str, typing.Any]) -> UserInfoModel:
        ...

    def get_urls(self) -> list[Url]:
        self.login_url = Url("login")
        self.auth_url = Url("authorize")
        return [self.login_url, self.auth_url]

    @abc.abstractmethod
    def routes(self):
        ...
