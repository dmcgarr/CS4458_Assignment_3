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
    salt = username + REALM_NAME + password
    hash = SHA256.new(salt.encode())
    return hash.hexdigest() # hexdigest returns the hexadecimal value of the salted hash value so it is equal to the value in the json file


def encrypt(key: bytes, data: Any) -> bytes:
    """Encrypts the given data using AES."""
    """use GCM for AES and dont forget the nonce"""
    """use pickle to serialize the data from the json object"""
    """should be able to encrypt any python object"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pickle.dumps(data))
    return cipher.nonce + ciphertext + tag


def decrypt(key: bytes, data: bytes) -> Any:
    """Decrypts the given message using AES."""
    """should retrun the exact object that was encrypted"""
    """should also return none if the message was not authentic"""
    nonce, ciphertext, tag = data[0:16], data[16:-16], data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        data = pickle.loads(plaintext)
        return data
    except(ValueError, pickle.UnpicklingError, EOFError):
        return None

class AuthenticationServer:
    """The authentication server in Kerberos."""

    def __init__(self) -> None:
        with open("users.json", "rb") as file:
            self.users = {k: bytes.fromhex(v) for k, v in json.load(file).items()}

    def request_authentication(self, username: str) -> Optional[Tuple[bytes, bytes]]:
        """Requests authentication for the given user from the authentication server."""
        """ checks whether the user is in the database, if so AS gets the clients"""
        """if not it returns none for invalid username or password"""
        """Should return none when no messages are returned"""

        # Message 1: client/TGS session key encrypted using client secret key (encrypt using secret key derived from username and password)
        # if its in the user data base, create key, 
        if (username in self.users):
            session_key = get_random_bytes(32)
            client_key = self.users[username]
            encrypted_session_key = encrypt(client_key, session_key)
        else:
            return None
        # Message 2: TGT encrypted using shared key between AS and TGS
        TGT = Ticket(username, session_key)
        encrypted_TGT = encrypt(AS_TGS_SHARED_KEY, TGT)

        return encrypted_session_key, encrypted_TGT


class TicketGrantingServer:
    """The ticket-granting server in Kerberos."""

    def request_authorization(
        self,
        tgt_encrypted: bytes,
        authenticator_encrypted: bytes,
    ) -> Optional[Tuple[bytes, bytes]]:
        """Requests service authorization from the ticket-granting server by using the given TGT and authenticator."""
        """need to compare the username of the message 3 (TGT) and username from message 4 (authenticator)"""
        # Message 5: client/FS session key encrypted using client/TGS session key
        #create new session key like done above in the AS
        # Message 6: service ticket encrypted using shared key between TGS and FS
        # create a Ticket and encrypt with TGS_FS_SHARED_KEY
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
        # compare username from message_7 (ticket_encrypted) and message_8 (authenticator_encrypted)
        #compare timestamps as well
        


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
        """client prints error messages if any stage of the kerberos fails"""
        authentication = AuthenticationServer().request_authentication(self.username)
        if (authentication): #check if None was returned
            # Message 3: client forwards message 2 (TGT) from AS to TGS (create)
            message_3 = authentication[1]
            
            # Message 4: authenticator encrypted using client/TGS session key (create)
            message_1 = authentication[0]
            """might need to check for None return"""
            TGS_session_key = decrypt(self.secret_key, message_1)
            client_authentication = Authenticator(self.username)
            encrypted_client_authentication = encrypt(TGS_session_key, client_authentication) # message 4
            # Send messages:
            TGT_authentication = TicketGrantingServer().request_authorization(message_3, encrypted_client_authentication)
            if (TGT_authentication):
                # Message 7: client forwards message 6 (service ticket) from TGS to FS (create)
                message_7 = TGT_authentication[1]
                # Message 8: authenticator encrypted using client/FS session key (create)
                message_5 = TGT_authentication[0]
                """might need to check for None return"""
                FS_session_key = decrypt(TGS_session_key, message_5)
                #create authenticator to send to FS and encrypt with FS_session_key above
                #send message to FS
                # once received, compare timestamps of sent authentication and received timestamp from FileResponse object (using equality)
                # then print data.
            else:
                print("something .........................................................")
        else:
            print("Failed to decrypt client/TGS session key.") 

""" use the following as messages for kerberos as needed and encrypted using the methods above"""
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
