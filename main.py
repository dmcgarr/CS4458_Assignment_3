import getpass
import json
import pickle
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

REALM_NAME = "@KERBEROS"

AS_TGS_SHARED_KEY = get_random_bytes(32)
TGS_FS_SHARED_KEY = get_random_bytes(32)


def derive_secret_key(username: str, password: str) -> bytes:
    """
    Derives the given user's secret key from the username and password.
    This one-way derivation function uses SHA256 as the hashing algorithm.
    The salt (combined username and realm name) is prepended to the given
    password so that two different encryption keys are generated for users
    with the same password.
    """
    salt = username + REALM_NAME 
    pass


def encrypt(key: bytes, data: Any) -> bytes:
    """Encrypts the given data using AES."""
    """use GCM for AES and dont forget the nonce"""
    """use pickle to serialize the data from the json object"""


def decrypt(key: bytes, data: bytes) -> Any:
    """Decrypts the given message using AES."""
    pass


class AuthenticationServer:
    """The authentication server in Kerberos."""

    def __init__(self) -> None:
        with open("users.json", "rb") as file:
            self.users = {k: bytes.fromhex(v) for k, v in json.load(file).items()}

    def request_authentication(self, username: str) -> Optional[Tuple[bytes, bytes]]:
        """Requests authentication for the given user from the authentication server."""

        # Message 1: client/TGS session key encrypted using client secret key
        # Message 2: TGT encrypted using shared key between AS and TGS
        pass


class TicketGrantingServer:
    """The ticket-granting server in Kerberos."""

    def request_authorization(
        self,
        tgt_encrypted: bytes,
        authenticator_encrypted: bytes,
    ) -> Optional[Tuple[bytes, bytes]]:
        """Requests service authorization from the ticket-granting server by using the given TGT and authenticator."""

        # Message 5: client/FS session key encrypted using client/TGS session key
        # Message 6: service ticket encrypted using shared key between TGS and FS
        pass


class FileServer:
    """The file server in Kerberos."""

    def request_file(
        self,
        filename: str,
        ticket_encrypted: bytes,
        authenticator_encrypted: bytes,
    ) -> Optional[bytes]:
        """Requests the given file from the file server by using the given service ticket and authenticator as authorization."""

        # Message 9: the file request response encrypted using the client/FS session key
        pass


class Client:
    """The client in Kerberos."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.secret_key = derive_secret_key(username, password)

    @classmethod
    def from_terminal(cls):
        """Creates a client object using user input from the terminal."""

        username = input("Username: ")
        password = getpass.getpass("Password: ")
        return cls(username, password)

    def get_file(self, filename: str):
        """Gets the given file from the file server."""

        # Message 3: client forwards message 2 (TGT) from AS to TGS
        # Message 4: authenticator encrypted using client/TGS session key
        # Message 7: client forwards message 6 (service ticket) from TGS to FS
        # Message 8: authenticator encrypted using client/FS session key
        pass


@dataclass(frozen=True)
class Ticket:
    """A ticket that acts as both a ticket-granting ticket (TGT) and a service ticket."""

    username: str
    session_key: bytes
    validity: float = field(init=False, default_factory=lambda: time.time() + 3600)


@dataclass(frozen=True)
class Authenticator:
    """An authenticator used by the client to confirm their identity with the various servers."""

    username: str
    timestamp: float = field(init=False, default_factory=time.time)


@dataclass(frozen=True)
class FileResponse:
    """A response to a file request that contains the file's data and a timestamp to confirm the file server's identity."""

    data: str
    timestamp: float


if __name__ == "__main__":
    client = Client.from_terminal()
    client.get_file("test.txt")
