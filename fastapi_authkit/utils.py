import fastapi
from authlib.jose import jwt


def get_full_url(request: fastapi.Request) -> str:
    if request.url.hostname:
        host: str = request.url.hostname
    else:
        raise RuntimeError("host is not verified")
    return request.url.scheme + "://" + host + ":" + str(request.url.port)
