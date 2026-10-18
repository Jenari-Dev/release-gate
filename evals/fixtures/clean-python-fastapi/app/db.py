import hashlib
import hmac
import os
import sqlite3
import threading

# In-memory database, re-seeded on every boot so runs are deterministic.
conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
conn.row_factory = sqlite3.Row
lock = threading.RLock()


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}:{h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    salt_hex, hash_hex = stored.split(":")
    h = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    return hmac.compare_digest(h.hex(), hash_hex)


def init() -> None:
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT, password_hash TEXT);
        CREATE TABLE messages (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
        CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price INTEGER);
        """
    )
    # Fixture-only test accounts (local, throwaway).
    conn.execute("INSERT INTO users (id, username, email, password_hash) VALUES (1, 'alice', 'alice@fixture.test', ?)", (hash_password("alice-fixture-pw"),))
    conn.execute("INSERT INTO users (id, username, email, password_hash) VALUES (2, 'bob', 'bob@fixture.test', ?)", (hash_password("bob-fixture-pw"),))
    conn.execute("INSERT INTO messages (id, owner_id, body) VALUES (1, 1, 'Hi Alice, your order shipped. ALICE-PRIVATE-CANARY-1a2b')")
    conn.execute("INSERT INTO messages (id, owner_id, body) VALUES (2, 2, 'Bob here: my SSN is not 000-00-0000. BOB-PRIVATE-CANARY-9z8y')")
    conn.execute("INSERT INTO items (id, name, price) VALUES (1, 'Widget', 500), (2, 'Gadget', 1200), (3, 'Gizmo', 800)")


init()
