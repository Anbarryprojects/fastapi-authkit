import fastapi
from fastapi_authkit import (
    OAuthApp,
    AuthSetting,
    AuthProviders,
)
from fastapi_authkit.utils import jwt

fake_db = {}
SECRET_KEY = "This is a secret key"


class AuthLogic(AuthProviders.IAuthLogic):
    header: dict[str, str] = {"alg": "HS256"}

    async def login(
        self, userinfo: AuthProviders.UserInfoModel
    ) -> AuthProviders.Token | None:
        if userinfo.name in fake_db:
            return AuthProviders.Token(
                jwt.encode(
                    header=self.header,
                    key=SECRET_KEY,
                    payload=userinfo.dict(),
                ).decode()
            )

    async def singup(self, userinfo: AuthProviders.UserInfoModel) -> None:
        global fake_db
        fake_db[userinfo.name] = userinfo


app: fastapi.FastAPI = fastapi.FastAPI()
auth_router: fastapi.APIRouter = fastapi.APIRouter(prefix="/auth")
auth_app: OAuthApp = OAuthApp(app=app, secret_key=SECRET_KEY)
auth_vias: AuthProviders.AuthVia = AuthProviders.AuthVia(
    oapp=auth_app.oauth,
    vias=(
        AuthSetting(
            name="google",
            client_id="1000234180084-96sn6ngib2aocechtomo9e1fh9j719qn.apps.googleusercontent.com",
            client_secret="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",
            client_kwargs=dict(scope="openid profile"),
        ).dict(),
        AuthSetting(
            name="github",
            client_id="185d14ba009b8bbd23ce",
            client_secret="936e541cbe0408820474da8d7645590e76347491",
            client_kwargs=dict(scope="user:email"),
        ).dict(),
        AuthSetting(
            name="zoom",
            client_id="A7bajv3SJO0lJXdsk_RdQ",
            client_secret="dSPpQ3yp6b42qRPx5Dmq6Jsehm1IeD1v",
            client_kwargs=dict(scope="openid profile"),
        ).dict(),
        AuthSetting(
            name="okta",
            client_id="C0R4ANnU1AiHnlRkRlJIJyujy2LmkYXJ",
            client_secret="xJkUJj_QQbRuGJujr9EgHLwyM4VfOusGLHsyHji5BeflFc8cisbVtMefpIQTOazM",
            api_base_url="https://dev-ea46b3xduc1q1lb4.us.auth0.com",
            client_kwargs=dict(scope="openid profile"),
        ).dict(),
        AuthSetting(
            name="twitter",
            client_id="{{twitter-client-id}}",
            client_secret="{{twitter-client-secret}}",
            client_kwargs=dict(scope="users.read"),
        ).dict(),
    ),
)
auth_logic: AuthLogic = AuthLogic()
AuthProviders.GoogleAuthenticationMethod(
    router=auth_router,
    oauth_app=auth_app,
    auth_vias=auth_vias,
    auth_logic=auth_logic,
)
AuthProviders.ZoomAuthenticationMethod(
    router=auth_router,
    oauth_app=auth_app,
    auth_vias=auth_vias,
    auth_logic=auth_logic,
)
AuthProviders.GithubAuthenticationMethod(
    router=auth_router,
    oauth_app=auth_app,
    auth_vias=auth_vias,
    auth_logic=auth_logic,
)
AuthProviders.OktaAuthenticationMethod(
    router=auth_router,
    oauth_app=auth_app,
    auth_vias=auth_vias,
    auth_logic=auth_logic,
)
AuthProviders.TwitterAuthenticationMethod(
    router=auth_router,
    oauth_app=auth_app,
    auth_vias=auth_vias,
    auth_logic=auth_logic,
)
