from __future__ import annotations
from datetime import datetime
import typing

from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client.apps import (
    StarletteOAuth1App,
    StarletteOAuth2App,
)
from authlib.integrations.starlette_client import OAuthError
from authlib.oidc.core.claims import UserInfo
import pydantic


Url = typing.NewType("Url", str)


class AuthVia:
    class Authenticator:
        def __init__(
            self,
            context: typing.Type[AuthVia],
            urls: list[Url],
            auth_class: typing.Optional[StarletteOAuth1App | StarletteOAuth2App],
        ) -> None:
            self.context: typing.Type[AuthVia] = context
            self.urls: list[Url] = urls
            self.__auth_class: typing.Optional[
                StarletteOAuth1App | StarletteOAuth2App
            ] = auth_class

        def get_auth_class(self) -> StarletteOAuth1App | StarletteOAuth2App:
            if self.__auth_class:
                return self.__auth_class
            raise AttributeError

        def __call__(self, url: Url) -> Url:
            if url in self.urls:
                return Url("/" + self.context.__name__.lower() + "/" + url)
            raise ValueError("url not registered")

    def __init__(
        self, vias: typing.Iterable[dict[str, typing.Any]], oapp: OAuth
    ) -> None:
        self.vias: typing.Iterable[dict[str, typing.Any]] = vias
        self.oapp: OAuth = oapp
        self.__methods: list[str] = []
        for via in self.vias:
            self.__methods.append(via["name"])

    def register(self, setting: dict[str, typing.Any]) -> None:
        self.oapp.register(overwrite=False, **setting)

    def get_setting(self, name: str) -> dict[str, typing.Any]:
        if name in self.__methods:
            for via in self.vias:
                if via["name"] == name:
                    return via
        raise ValueError(name + " method not registered.")

    def __call__(
        self,
        via: str,
        urls: list[Url],
    ) -> Authenticator:
        if via in self.__methods:
            cls: typing.Type[AuthVia] = type(via, (self.__class__,), dict())
            try:
                return self.Authenticator(
                    cls,
                    urls,
                    getattr(
                        self.oapp,
                        via,
                    ),
                )
            except AttributeError:
                pass
        raise ValueError(f"{via} auth method not registered")

    def __repr__(self) -> str:
        return self.__class__.__name__.lower()


class UserInfoModel(pydantic.BaseModel):
    sub: typing.Optional[str] = pydantic.Field(None)
    name: typing.Optional[str] = pydantic.Field(None)
    given_name: typing.Optional[str] = pydantic.Field(None)
    family_name: typing.Optional[str] = pydantic.Field(None)
    middle_name: typing.Optional[str] = pydantic.Field(None)
    nickname: typing.Optional[str] = pydantic.Field(None)
    preferred_username: typing.Optional[str] = pydantic.Field(None)
    profile: typing.Optional[str] = pydantic.Field(None)
    picture: typing.Optional[str] = pydantic.Field(None)
    website: typing.Optional[str] = pydantic.Field(None)
    email: typing.Optional[str] = pydantic.Field(None)
    email_verified: typing.Optional[str] | typing.Optional[int] | typing.Optional[
        bool
    ] = pydantic.Field(None)
    gender: typing.Optional[str] = pydantic.Field(None)
    birthdate: typing.Optional[str] = pydantic.Field(None)
    zoneinfo: typing.Optional[str] = pydantic.Field(None)
    locale: typing.Optional[str] = pydantic.Field(None)
    phone_number: typing.Optional[str] = pydantic.Field(None)
    phone_number_verified: typing.Optional[str] | typing.Optional[
        int
    ] | typing.Optional[bool] = pydantic.Field(None)
    address: typing.Optional[str] = pydantic.Field(None)
    updated_at: typing.Optional[str] = pydantic.Field(None)
    extra: typing.Optional[dict[str, typing.Any]] = pydantic.Field(None)

    @pydantic.root_validator(pre=True)
    def build_extra(cls, values: dict[str, typing.Any]) -> dict[str, typing.Any]:
        all_required_field_names = {
            field.alias for field in cls.__fields__.values() if field.alias != "extra"
        }  # to support alias

        extra: dict[str, typing.Any] = {}
        for field_name in list(values):
            if field_name not in all_required_field_names:
                extra[field_name] = values.pop(field_name)
        values["extra"] = extra
        return values
