from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from .db_utils import db_utils
from .models import wrapped_models as wrapped_models_func
from .methods import wrapped_methods


async def init_async_db(test=False):
    name = "test" if test else "main"
    engine = create_async_engine(fr'sqlite+aiosqlite:///./{name}.db', future=True, echo=False)

    session = sessionmaker(
        engine, expire_on_commit=False, class_=AsyncSession
    )

    base = declarative_base()
    db_utils.set_base(base)
    wrapped_models = await wrapped_models_func(base)

    async with engine.begin() as conn:
        await conn.run_sync(base.metadata.create_all)

    addresses = await wrapped_methods(wrapped_models, session)
    return addresses
