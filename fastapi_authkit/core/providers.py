import typing
import fastapi
from httpx import Response

from ..utils import get_full_url

from .. import OAuthApp

from .oauth import AuthVia
from .oauth import UserInfo
from .oauth import OAuthError
from .oauth import UserInfoModel


from ..interfaces.logics import IAuthLogic
from ..interfaces.logics import Token
from ..interfaces.provider import AuthenticationMethod
from ..interfaces.provider import TokenResponse


class GoogleAuthenticationMethod(AuthenticationMethod):
    def __init__(
        self,
        router: fastapi.APIRouter,
        oauth_app: OAuthApp,
        auth_vias: AuthVia,
        auth_logic: IAuthLogic,
    ) -> None:
        super().__init__(
            name="google",
            router=router,
            oauth_app=oauth_app,
            auth_vias=auth_vias,
            auth_logic=auth_logic,
        )

    def configure(self):
        self.settings.server_metadata_url = (
            "https://accounts.google.com/.well-known/openid-configuration"
        )

    def create_userinfo(self, userinfo: dict[str, typing.Any]) -> UserInfoModel:
        return UserInfoModel(**UserInfo(userinfo))

    def routes(self):
        @self.router.get(self.authenticator(self.login_url))
        async def login(request: fastapi.Request) -> fastapi.responses.RedirectResponse:
            redirect_uri: str = (
                get_full_url(request=request)
                + self.router.prefix
                + self.authenticator(self.auth_url)
            )
            return await self.authenticator.get_auth_class().authorize_redirect(
                request,
                redirect_uri=redirect_uri,
            )

        @self.router.get(
            self.authenticator(self.auth_url),
            responses={
                201: {
                    "description": "when a user has not already registered, this api will"
                    "signup first and next step will login the user,"
                },
            },
            response_model=TokenResponse,
        )
        async def authorize(
            request: fastapi.Request, response: fastapi.Response
        ) -> TokenResponse:
            auth_token: typing.Any = (
                await self.authenticator.get_auth_class().authorize_access_token(
                    request
                )
            )
            userinfo: UserInfoModel = self.create_userinfo(auth_token["userinfo"])
            # If user has already registered by its github account will login
            # easily, otherwize will invoke the signup method before relogin
            # flow.

            token: str | None = await self.auth_logic.login(userinfo=userinfo)
            if token:
                return TokenResponse(access_token=token, token_type="bearer")

            # create a user account
            await self.auth_logic.singup(userinfo=userinfo)

            # login the user.
            token = await self.auth_logic.login(userinfo)
            if token:
                response.status_code = fastapi.status.HTTP_201_CREATED
                return TokenResponse(access_token=token, token_type="bearer")
            raise fastapi.HTTPException(
                fastapi.status.HTTP_422_UNPROCESSABLE_ENTITY,
            )


class ZoomAuthenticationMethod(AuthenticationMethod):
    def __init__(
        self,
        router: fastapi.APIRouter,
        oauth_app: OAuthApp,
        auth_vias: AuthVia,
        auth_logic: IAuthLogic,
    ) -> None:
        super().__init__("zoom", router, oauth_app, auth_vias, auth_logic)

    def configure(self):
        self.settings.authorize_url = "https://zoom.us/oauth/authorize"
        self.settings.access_token_url = "https://zoom.us/oauth/token"
        self.settings.api_base_url = "https://api.zoom.us/"

    def create_userinfo(self, userinfo: dict[str, typing.Any]) -> UserInfoModel:
        return UserInfoModel(
            sub=userinfo["id"],
            name=userinfo["display_name"],
            family_name=userinfo["last_name"],
            given_name=userinfo["first_name"],
            middle_name="",
            nickname="",
            email=userinfo["email"],
            preferred_username=userinfo["display_name"],
            address=userinfo["location"],
            birthdate="",
            zoneinfo=userinfo["timezone"],
            email_verified=userinfo["verified"],
            picture=userinfo["pic_url"],
            locale=userinfo["location"],
            gender="",
            phone_number=userinfo["phone_number"],
            phone_number_verified=userinfo["verified"],
            profile="",
            updated_at=userinfo["last_login_time"],
            website="",
            extra=userinfo,
        )

    def routes(self):
        @self.router.get(self.authenticator(self.login_url))
        async def login(request: fastapi.Request) -> fastapi.responses.RedirectResponse:
            redirect_uri: str = (
                get_full_url(request=request)
                + self.router.prefix
                + self.authenticator(self.auth_url)
            )
            return await self.authenticator.get_auth_class().authorize_redirect(
                request,
                redirect_uri=redirect_uri,
            )

        @self.router.get(
            self.authenticator(self.auth_url),
            responses={
                201: {
                    "description": "when a user has not already registered, this api will"
                    "signup first and next step will login the user,"
                },
            },
            response_model=TokenResponse,
        )
        async def authorize(
            request: fastapi.Request, response: fastapi.Response
        ) -> TokenResponse:
            auth_token: typing.Any = (
                await self.authenticator.get_auth_class().authorize_access_token(
                    request
                )
            )

            resp: Response = await self.authenticator.get_auth_class().get(
                "v2/users/me",
                params={"skip_status": True},
                token=auth_token,
            )
            resp.raise_for_status()
            userinfo: UserInfoModel = self.create_userinfo(resp.json())
            # If user has already registered by its github account will login
            # easily, otherwize will invoke the signup method before relogin
            # flow.

            token: str | None = await self.auth_logic.login(userinfo=userinfo)
            if token:
                return TokenResponse(access_token=token, token_type="bearer")

            # create a user account
            await self.auth_logic.singup(userinfo=userinfo)

            # login the user.
            token = await self.auth_logic.login(userinfo)
            if token:
                response.status_code = fastapi.status.HTTP_201_CREATED
                return TokenResponse(access_token=token, token_type="bearer")
            raise fastapi.HTTPException(
                fastapi.status.HTTP_422_UNPROCESSABLE_ENTITY,
            )


class GithubAuthenticationMethod(AuthenticationMethod):
    def __init__(
        self,
        router: fastapi.APIRouter,
        oauth_app: OAuthApp,
        auth_vias: AuthVia,
        auth_logic: IAuthLogic,
    ) -> None:
        super().__init__("github", router, oauth_app, auth_vias, auth_logic)

    def create_userinfo(self, userinfo: dict[str, typing.Any]) -> UserInfoModel:
        if "email" not in userinfo:
            raise OAuthError(
                description="Your github account doesn't have any public email."
                "\nplease add a publick email to your github account.",
                uri=userinfo["html_url"],
            )
        name: str = userinfo["name"]
        first_name, last_name = name.split(" ")
        return UserInfoModel(
            sub=str(userinfo["id"]),
            name=userinfo["login"],
            address="",
            birthdate="",
            email=userinfo["email"],
            email_verified=True,
            extra=userinfo,
            family_name=last_name,
            given_name=first_name,
            gender="",
            locale=userinfo["location"] or "",
            middle_name=userinfo["company"],
            nickname=name,
            phone_number="",
            phone_number_verified=False,
            picture=userinfo["avatar_url"],
            preferred_username=userinfo["node_id"],
            profile=userinfo["html_url"],
            updated_at=userinfo["updated_at"],
            website=userinfo["html_url"],
            zoneinfo="",
        )

    def configure(self):
        self.settings.access_token_url = "https://github.com/login/oauth/access_token"
        self.settings.access_token_params = None
        self.settings.authorize_url = "https://github.com/login/oauth/authorize"
        self.settings.authorize_params = None
        self.settings.api_base_url = "https://api.github.com/"
        self.settings.client_kwargs.update(
            {
                "token_endpoint_auth_method": "client_secret_basic",
                "token_placement": "header",
            }
        )

    def routes(self):
        @self.router.get(self.authenticator(self.login_url))
        async def login(request: fastapi.Request) -> fastapi.responses.RedirectResponse:
            redirect_uri: str = (
                get_full_url(request=request)
                + self.router.prefix
                + self.authenticator(self.auth_url)
            )
            return await self.authenticator.get_auth_class().authorize_redirect(
                request,
                redirect_uri=redirect_uri,
            )

        @self.router.get(
            self.authenticator(self.auth_url),
            responses={
                201: {
                    "description": "when a user has not already registered, this api will"
                    "signup first and next step will login the user,"
                },
            },
            response_model=TokenResponse,
        )
        async def authorize(
            request: fastapi.Request, response: fastapi.Response
        ) -> TokenResponse:
            auth_token: typing.Any = (
                await self.authenticator.get_auth_class().authorize_access_token(
                    request
                )
            )

            resp: Response = await self.authenticator.get_auth_class().get(
                "user",
                params={"skip_status": True},
                token=auth_token,
            )
            resp.raise_for_status()
            userinfo: UserInfoModel = self.create_userinfo(resp.json())
            # If user has already registered by its github account will login
            # easily, otherwize will invoke the signup method before relogin
            # flow.

            token: str | None = await self.auth_logic.login(userinfo=userinfo)
            if token:
                return TokenResponse(access_token=token, token_type="bearer")

            # create a user account
            await self.auth_logic.singup(userinfo=userinfo)

            # login the user.
            token = await self.auth_logic.login(userinfo)
            if token:
                response.status_code = fastapi.status.HTTP_201_CREATED
                return TokenResponse(access_token=token, token_type="bearer")
            raise fastapi.HTTPException(
                fastapi.status.HTTP_422_UNPROCESSABLE_ENTITY,
            )


class TwitterAuthenticationMethod(AuthenticationMethod):
    def __init__(
        self,
        router: fastapi.APIRouter,
        oauth_app: OAuthApp,
        auth_vias: AuthVia,
        auth_logic: IAuthLogic,
    ) -> None:
        super().__init__("twitter", router, oauth_app, auth_vias, auth_logic)

    def configure(self):
        twitter_address = "https://api.twitter.com"
        self.settings.api_base_url = twitter_address + "/1.1/"
        self.settings.request_token_url = f"{twitter_address}/oauth/request_token"
        self.settings.access_token_url = f"{twitter_address}/oauth/access_token"
        self.settings.authorize_url = f"{twitter_address}/oauth/authenticate"

    def create_userinfo(self, userinfo: dict[str, typing.Any]) -> UserInfoModel:
        return UserInfoModel(
            name=userinfo["name"],
            email=userinfo["email"],
            sub=userinfo["sub"],
            given_name=None,
            family_name=None,
            middle_name=None,
            nickname=None,
            preferred_username=None,
            profile=None,
            picture=None,
            website=None,
            email_verified=None,
            gender=None,
            birthdate=None,
            zoneinfo=None,
            locale=None,
            phone_number=None,
            phone_number_verified=None,
            address=None,
            updated_at=None,
            extra=userinfo,
        )

    def routes(self):
        @self.router.get(self.authenticator(self.login_url))
        async def login(request: fastapi.Request) -> fastapi.responses.RedirectResponse:
            redirect_uri: str = (
                get_full_url(request=request)
                + self.router.prefix
                + self.authenticator(self.auth_url)
            )
            return await self.authenticator.get_auth_class().authorize_redirect(
                request,
                redirect_uri=redirect_uri,
            )

        @self.router.get(
            self.authenticator(self.auth_url),
            responses={
                201: {
                    "description": "when a user has not already registered, this api will"
                    "signup first and next step will login the user,"
                },
            },
            response_model=TokenResponse,
        )
        async def authorize(
            request: fastapi.Request, response: fastapi.Response
        ) -> TokenResponse:
            auth_token: typing.Any = (
                await self.authenticator.get_auth_class().authorize_access_token(
                    request
                )
            )
            url = "account/verify_credentials.json"
            resp: Response = await self.authenticator.get_auth_class().get(
                url, params={"skip_status": True}, token=auth_token
            )
            resp.raise_for_status()
            userinfo = resp.json()
            # If user has already registered by its github account will login
            # easily, otherwize will invoke the signup method before relogin
            # flow.

            token: str | None = await self.auth_logic.login(userinfo=userinfo)
            if token:
                return TokenResponse(access_token=token, token_type="bearer")

            # create a user account
            await self.auth_logic.singup(userinfo=userinfo)

            # login the user.
            token = await self.auth_logic.login(userinfo)
            if token:
                response.status_code = fastapi.status.HTTP_201_CREATED
                return TokenResponse(access_token=token, token_type="bearer")
            raise fastapi.HTTPException(
                fastapi.status.HTTP_422_UNPROCESSABLE_ENTITY,
            )


class OktaAuthenticationMethod(AuthenticationMethod):
    def __init__(
        self,
        router: fastapi.APIRouter,
        oauth_app: OAuthApp,
        auth_vias: AuthVia,
        auth_logic: IAuthLogic,
    ) -> None:
        super().__init__(
            "okta",
            router,
            oauth_app,
            auth_vias,
            auth_logic,
        )

    def configure(self):
        api_base_url = self.settings.api_base_url
        if api_base_url:
            self.settings.access_token_url = api_base_url + "/oauth/token"
            self.settings.authorize_url = api_base_url + "/authorize"
            self.settings.server_metadata_url = api_base_url + "/.well-known/jwks.json"
        else:
            raise ValueError("Okta Domain/API URL didn't verify.")

    def create_userinfo(self, userinfo: dict[str, typing.Any]) -> UserInfoModel:
        return UserInfoModel(
            name=userinfo["nickname"],
            email=userinfo["name"],
            address=userinfo.get("address", ""),
            given_name=userinfo.get("given_name", ""),
            middle_name=userinfo.get("middle_name", ""),
            family_name=userinfo.get("family_name", ""),
            birthdate=userinfo.get("birthdate", ""),
            email_verified=userinfo.get("email_verified", ""),
            gender=userinfo.get("gender", ""),
            locale=userinfo.get("locale", ""),
            phone_number=userinfo.get("phone_number", ""),
            nickname=userinfo.get("nickname", ""),
            phone_number_verified=userinfo.get("phone_number_verified", ""),
            picture=userinfo.get("picture", ""),
            preferred_username=userinfo.get("preferred_username", ""),
            sub=userinfo["sub"],
            updated_at=userinfo["updated_at"],
            profile=userinfo.get("profile", ""),
            website=userinfo.get("website", ""),
            zoneinfo=userinfo.get("zoneinfo", ""),
            extra=userinfo,
        )

    def routes(self):
        @self.router.get(self.authenticator(self.login_url))
        async def login(request: fastapi.Request) -> fastapi.responses.RedirectResponse:
            redirect_uri: str = (
                get_full_url(request=request)
                + self.router.prefix
                + self.authenticator(self.auth_url)
            )
            return await self.authenticator.get_auth_class().authorize_redirect(
                request,
                redirect_uri=redirect_uri,
            )

        @self.router.get(
            self.authenticator(self.auth_url),
            responses={
                201: {
                    "description": "when a user has not already registered, this api will"
                    "signup first and next step will login the user,"
                },
            },
            response_model=TokenResponse,
        )
        async def authorize(
            request: fastapi.Request, response: fastapi.Response
        ) -> TokenResponse:
            server_metadata: dict = getattr(
                self.authenticator.get_auth_class(), "server_metadata"
            )
            if server_metadata:
                server_metadata["jwks_uri"] = self.settings.server_metadata_url
            auth_token: typing.Any = (
                await self.authenticator.get_auth_class().authorize_access_token(
                    request
                )
            )
            userinfo: UserInfoModel = self.create_userinfo(auth_token["userinfo"])
            # If user has already registered by its github account will login
            # easily, otherwize will invoke the signup method before relogin
            # flow.

            token: str | None = await self.auth_logic.login(userinfo=userinfo)
            if token:
                return TokenResponse(access_token=token, token_type="bearer")

            # create a user account
            await self.auth_logic.singup(userinfo=userinfo)

            # login the user.
            token = await self.auth_logic.login(userinfo)
            if token:
                response.status_code = fastapi.status.HTTP_201_CREATED
                return TokenResponse(access_token=token, token_type="bearer")
            raise fastapi.HTTPException(
                fastapi.status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
