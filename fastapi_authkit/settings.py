from typing import Any, Optional
from pydantic import BaseSettings, Field


class __SETTINGS(BaseSettings):
    ...


class OIDC_SETTINGS(__SETTINGS):
    name: str
    client_id: str
    client_secret: str
    access_token_url: Optional[str] = None
    access_token_params: Optional[str] = None
    authorize_url: Optional[str] = None
    authorize_params: Optional[str] = None
    api_base_url: Optional[str] = None
    request_token_url: Optional[str] = None
    server_metadata_url: Optional[str] = None
    client_kwargs: dict[str, Any] = Field(default_factory=dict)


class URLSAFE_SETTINGS(__SETTINGS):
    urlsafe_salt: Optional[str] = None
    urlsafe_max_age: Optional[int] = None


class SETTINGS(
    OIDC_SETTINGS,
    URLSAFE_SETTINGS,
):
    ...
