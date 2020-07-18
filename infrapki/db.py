from sqlalchemy import Binary, Boolean, Column, DateTime, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class IssuedCert(Base):
    __tablename__ = "issued_cert"

    serial = Column(Binary, primary_key=True)
    cert = Column(Binary)
    revoked = Column(Boolean, default=False)
