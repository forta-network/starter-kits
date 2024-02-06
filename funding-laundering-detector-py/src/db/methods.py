from sqlalchemy.future import select


async def wrapped_methods(wrapped_models: list, async_session):
    return Methods(wrapped_models[0], async_session)


def wrap_async(func):
    async def wrapper(*args, **kwargs):
        async with args[0]._session() as session:
            async with session.begin():
                kwargs = {**kwargs, **{'session': session}}
                result = await func(*args, **kwargs)
                return result

    return wrapper


class Methods:

    def __init__(self, model: object(), session):
        self.__model = model
        self._session = session

    @wrap_async
    async def commit(self, session):
        await session.commit()

    @wrap_async
    async def paste_row(self, kwargs, session):
        session.add(self.__model(**kwargs))
        await session.flush()

    @wrap_async
    async def get_all_rows(self, session) -> tuple or None:
        q = await session.execute(select(self.__model))
        data = q.scalars().all()
        return data
