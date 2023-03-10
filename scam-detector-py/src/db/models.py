from sqlalchemy import Column, String, Float, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base


async def wrapped_models(Base: declarative_base):
    class Features(Base):
        __tablename__ = 'features'

        address = Column(String, primary_key=True)
        last_updated = Column(TIMESTAMP, primary_key=True)
        f1 = Column(Float)

    return Features
