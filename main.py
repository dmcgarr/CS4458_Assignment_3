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
    # create salt and encode to bytes
    salt = f"{username}{REALM_NAME}".encode()
    # encode password to bytes
    password_bytes = password.encode()
    # create hash
    hash = SHA256.new()
    # hash salt
    hash.update(salt)
    # hash password
    hash.update(password_bytes)
    # get the digest from the hash
    secret_key = hash.digest()
    return secret_key # this value will match the hex value of the password in the json file once read in


def encrypt(key: bytes, data: Any) -> bytes:
    """Encrypts the given data using AES."""
    # create cipher
    cipher = AES.new(key, AES.MODE_GCM)
    # encrypt data
    ciphertext, tag = cipher.encrypt_and_digest(pickle.dumps(data))
    # return bytestring of nonce, cipher and tag to use for decryption
    return cipher.nonce + ciphertext + tag


def decrypt(key: bytes, data: bytes) -> Any:
    """Decrypts the given message using AES."""
    # parse input for nonce, ciphertext and tag
    nonce, ciphertext, tag = data[0:16], data[16:-16], data[-16:]
    # create cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        # decrypt data
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        # load object data
        data = pickle.loads(plaintext)
        return data
    except(ValueError, pickle.UnpicklingError, EOFError):
        # if theres an error with loading data from pickle, not verified or EOFError
        return None

class AuthenticationServer:
    """The authentication server in Kerberos."""

    def __init__(self) -> None:
        with open("users.json", "rb") as file:
            self.users = {k: bytes.fromhex(v) for k, v in json.load(file).items()}

    def request_authentication(self, username: str) -> Optional[Tuple[bytes, bytes]]:
        """Requests authentication for the given user from the authentication server."""
        # if its in the user data base, create messages, else return none 
        if (username in self.users):
            # Message 1: client/TGS session key encrypted using client secret key (encrypt using secret key derived from username and password)
            # create session key and encrypt it
            session_key = get_random_bytes(32)
            client_key = self.users[username]
            encrypted_session_key = encrypt(client_key, session_key)
            # Message 2: TGT encrypted using shared key between AS and TGS
            TGT = Ticket(username, session_key)
            encrypted_TGT = encrypt(AS_TGS_SHARED_KEY, TGT)
            return encrypted_session_key, encrypted_TGT
        else:
            return None
        


class TicketGrantingServer:
    """The ticket-granting server in Kerberos."""

    def request_authorization(
        self,
        tgt_encrypted: bytes,
        authenticator_encrypted: bytes,
    ) -> Optional[Tuple[bytes, bytes]]:
        """Requests service authorization from the ticket-granting server by using the given TGT and authenticator."""
        # decrypt TGT
        TGT_decrypted = decrypt(AS_TGS_SHARED_KEY, tgt_encrypted)
        if (tgt_encrypted): # check if ticket was successfully decrypted
            # get session key from decrypted TGT
            client_TGS_session_key = TGT_decrypted.session_key
            # decrypt authentication
            authenticator_decrypted = decrypt(client_TGS_session_key, authenticator_encrypted)
            if (authenticator_decrypted): # check if authenticator was successfully decrypted
                # get username from TGT
                username_TGT = TGT_decrypted.username
                # get username from authenticator
                username_authenticator = authenticator_decrypted.username
                if (username_TGT == username_authenticator): # check if usernames match
                    # Message 5: client/FS session key encrypted using client/TGS session key
                    session_key = get_random_bytes(32)
                    encrypted_session_key = encrypt(client_TGS_session_key, session_key)
                    # Message 6: service ticket encrypted using shared key between TGS and FS
                    TGT = Ticket(username_authenticator, session_key)
                    encrypted_TGT_2 = encrypt(TGS_FS_SHARED_KEY, TGT)
                    return encrypted_session_key, encrypted_TGT_2
                else:
                    return None
            else:
                return None
        else:
            return None


class FileServer:
    """The file server in Kerberos."""

    def request_file(
        self,
        filename: str,
        ticket_encrypted: bytes,
        authenticator_encrypted: bytes,
    ) -> Optional[bytes]:
        """Requests the given file from the file server by using the given service ticket and authenticator as authorization."""
        # decrypt TGT
        decrypted_ticket = decrypt(TGS_FS_SHARED_KEY, ticket_encrypted)
        if (decrypted_ticket): # check if ticket was successfully decrypted
            # get session key from decrypted message
            client_FS_session_key = decrypted_ticket.session_key
            # decrypt authenticator
            authenticator_decrypted = decrypt(client_FS_session_key, authenticator_encrypted)
            if (authenticator_decrypted): # check if decryption failed
                # compare usernames and timestamps of TGT and authentication messages
                if (authenticator_decrypted.username == decrypted_ticket.username and authenticator_decrypted.timestamp < decrypted_ticket.validity):
                    # Message 9: the file request response encrypted using the client/FS session key
                    with open(filename, 'r') as file:
                        data = file.read()
                    response = FileResponse(data, authenticator_decrypted.timestamp)
                    message_9 = encrypt(client_FS_session_key, response)
                    return message_9
            else:
                return None
        else:
            return None
        


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
        # send authentication to AS
        authentication = AuthenticationServer().request_authentication(self.username)
        if (authentication): # to check if None was returned
            # Message 3: client forwards message 2 (TGT) from AS to TGS (create)
            message_3 = authentication[1]
            
            # Message 4: authenticator encrypted using client/TGS session key (create)
            message_1 = authentication[0]
            TGS_session_key = decrypt(self.secret_key, message_1)
            if (TGS_session_key): # check if decryption failed
                client_authentication = Authenticator(self.username)
                encrypted_client_authentication = encrypt(TGS_session_key, client_authentication) # message 4
                # Send messages:
                TGT_authentication = TicketGrantingServer().request_authorization(message_3, encrypted_client_authentication)
                if (TGT_authentication):
                    # Message 7: client forwards message 6 (service ticket) from TGS to FS (create)
                    message_7 = TGT_authentication[1]
                    # encrypted session key
                    message_5 = TGT_authentication[0]
                    FS_session_key = decrypt(TGS_session_key, message_5)
                    if (FS_session_key): # check if decryption failed
                        # Message 8: authenticator encrypted using client/FS session key (create)
                        FS_authenticator = Authenticator(self.username)
                        message_8 = encrypt(FS_session_key, FS_authenticator) # encrypted Ticket 
                        #send message to FS
                        file_encrypted = FileServer().request_file(filename, message_7, message_8)
                        if (file_encrypted): #check if file is not None
                            #decrypt file using session key
                            file_decrypted = decrypt(FS_session_key, file_encrypted)
                            if (file_decrypted): #check if decryption was successful
                                if (FS_authenticator.timestamp == file_decrypted.timestamp):
                                    print(f"Retreived {filename} from FS:")
                                    print(file_decrypted.data)
                                else:
                                    print("Failed due to invalid timestamp.")
                            else:
                                print("Failed to decrypt file from FS.")
                        else:
                            print("Failed to access FS.")
                    else:
                        print("Failed to decrypt FS session key.")
                else:
                    print("Failed to access TGS.")
            else:
                print("Failed to decrypt TGS session key.")
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
