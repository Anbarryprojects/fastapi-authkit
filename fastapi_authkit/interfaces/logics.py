import abc
from typing import Any, NewType
from ..core.oauth import UserInfoModel

Token = NewType("Token", str)


class IAuthLogic(abc.ABC):
    @abc.abstractmethod
    async def login(self, userinfo: UserInfoModel) -> Token | None:
        ...

    @abc.abstractmethod
    async def singup(self, userinfo: UserInfoModel) -> None:
        ...
