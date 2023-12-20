from sqlalchemy import Column, String, Integer, Boolean
from sqlalchemy.ext.declarative import declarative_base


async def wrapped_models(Base: declarative_base):
    class Addresses(Base):
        __tablename__ = 'addresses'

        id = Column(Integer, primary_key=True, autoincrement=True)
        address = Column(String)
        address_type = Column(String)
        is_eoa = Column(Boolean)

    return [Addresses]
