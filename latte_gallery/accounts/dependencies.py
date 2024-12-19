from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from latte_gallery.accounts.security import decode_access_token
from sqlalchemy.ext.asyncio import AsyncSession
from latte_gallery.core.dependencies import session
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/accounts/token")

async def get_current_user(token: str, session: AsyncSession = Depends(session)):
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительный токен",
            headers={"WWW-Authenticate": "Bearer"},
        )
    login = payload.get("sub")
    if not login:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Недействительный токен")

    from latte_gallery.accounts.repository import AccountRepository
    account_repo = AccountRepository()
    user = await account_repo.find_by_login(login, session)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")
    
    return user
