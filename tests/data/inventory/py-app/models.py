from dataclasses import dataclass

from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    email = Column(String)
    display_name = Column(String)
    password_hash = Column(String)
    last_seen_ip = Column(String)
    # nickname = Column(String)   <- removed, must not be reported


class Profile(BaseModel):
    contact: EmailStr
    bio: str
    nickname: str
    page_size: int = 20


@dataclass
class Payment:
    iban: str
    amount: int
