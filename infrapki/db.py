from sqlalchemy import LargeBinary, Boolean, Column, DateTime, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class IssuedCert(Base):
    __tablename__ = "issued_cert"

    serial = Column(LargeBinary, primary_key=True)
    cert = Column(LargeBinary)
    revoked = Column(Boolean, default=False)
