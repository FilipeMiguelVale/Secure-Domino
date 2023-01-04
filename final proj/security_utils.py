import datetime

from OpenSSL import crypto
from PyKCS11 import *
# DH
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import hashlib
import hmac
import Colors

def hmac_sha512(msg, key):
    msgc = msg.copy()
    if isinstance(msgc, str):
        msgc = bytes(msgc, encoding='utf-8')
    elif isinstance(msgc, bytes):
        msgc = msgc
    elif isinstance(msg,dict):
        if "tileplayed" in msgc:
            msgc["tileplayed"] = str(msgc["tileplayed"])

        if "in_table"in msgc:
            aux = []
            for p in msgc["in_table"]:
                aux.append(str(p))
            msgc["in_table"] = aux
        msgc = bytes(str(msgc), encoding='utf-8')
    else:
        msgc = bytes(str(msgc), encoding='utf-8')

    return hmac.new(msgc, key, hashlib.sha512).digest()

def toBytes(data):
    if isinstance(data, str):
        return bytes(data, "utf -8")
    if isinstance(data, bytes):
        return data
    if isinstance(data, tuple):
        return bytes("""['""" + data[0] + """',""" + str(data[1]) + ']', "utf -8")


def createSymmKey(key_length=24):
    return os.urandom(key_length)


def cipherSymKey(key, data):
    iv = b"0" * 16
    encryptor = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()).encryptor()
    data = encryptor.update(data) + encryptor.finalize()
    return data


def decipherSymKey(key, data):
    iv = b"0" * 16
    decryptor = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()).decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    return data


def createAsymKeys(key_size=1024):
    priv_key = rsa.generate_private_key(65537, key_size, default_backend())
    pub_key = priv_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub_key, priv_key


def cipherAsymKey(pub_key, data):
    pub_key = load_pem_public_key(pub_key, default_backend())
    data = toBytes(data)
    maxLen = (pub_key.key_size // 8) - 2 * hashes.SHA256.digest_size - 2
    chunk_data = [data[i:i + maxLen] for i in range(0, len(data), maxLen)]
    ciphered_data = b''
    for chunck in chunk_data:
        ciphered_data += pub_key.encrypt(chunck, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return ciphered_data


def decipherAsymKey(priv_key, data):
    maxLen = priv_key.key_size // 8
    chunk_data = [data[i:i + maxLen] for i in range(0, len(data), maxLen)]
    deciphered_data = b''
    for chunck in chunk_data:
        deciphered_data += priv_key.decrypt(chunck, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return deciphered_data.decode('utf-8')

def load_server_pub_key():
    with open("Client/Server_pub.pem", "rb") as f:
        public = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
    return public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)

def gen_server_certificate(socket):

    with open("Server/Server_priv.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), None, backend=default_backend()
        )

    public_key = private_key.public_key()

    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 365 * 5))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(socket.gethostname()),
            x509.DNSName('*.%s' % socket.gethostname()),
            x509.DNSName('localhost'),
            x509.DNSName('*.localhost'),
        ]),
        critical=False)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend())

    return (certificate.public_bytes(serialization.Encoding.PEM),
            private_key,
            private_key.public_key())

def verify_cert_pubkey(certificate, pub_key):
    certificate = x509.load_pem_x509_certificate(certificate, default_backend())
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    print(Colors.BCyan+"Public key received from server: "+Colors.Color_Off, pub_key)
    print(Colors.BCyan+"Public key on the certificate: "+Colors.Color_Off, public_key)
    return public_key == pub_key


class DH(object):
    def __init__(self, generator=2, key_size=1024):
        print("Generating DH parameters")
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2

        params_numbers = dh.DHParameterNumbers(p, g)
        # parameters = params_numbers.parameters(default_backend())
        self.parameters = params_numbers.parameters(default_backend())
        # Generate a private key for use in the exchange.
        print("Generating private_key")
        self.private_key = self.parameters.generate_private_key()
        print("Generating public_key")
        self.public_key = self.private_key.public_key()
        self.peer_pub_key = None
        self.full_key = None
        self.partial_key = None

    def pulicKeyToPEM(self):
        return self.public_key.public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)

    def pemToKey(pub_key):
        return load_pem_public_key(pub_key, default_backend())

    def loadPeerPubKey(self, peer_pub_key, pem=True):
        if not pem:
            self.peer_pub_key = DH.pemToKey(peer_pub_key)
        else:
            self.peer_pub_key = peer_pub_key

    def generate_partial_key(self):
        assert self.peer_pub_key != None
        self.partial_key = self.private_key.exchange(self.peer_pub_key)

    def generate_full_key(self, length=32, salt=None, info=b'handshake data'):
        assert self.partial_key != None
        self.full_key = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info,
                             backend=default_backend()).derive(self.partial_key)


if __name__ == "__main__":
    # Generate some parameters. These can be reused.
    print("Generating parameters")
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    # Generate a private key for use in the exchange.
    print("Generating server_private_key")
    server_private_key = parameters.generate_private_key()
    # In a real handshake the peer is a remote client. For this
    # example we'll generate another local private key though. Note that in
    # a DH handshake both peers must agree on a common set of parameters.
    print("Generating peer_private_key")
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    peer_private_key = parameters.generate_private_key()
    print("Generating shared_key")
    shared_key = server_private_key.exchange(peer_private_key.public_key())
    # Perform key derivation.
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', ).derive(shared_key)

    # And now we can demonstrate that the handshake performed in the
    # opposite direction gives the same final value
    same_shared_key = peer_private_key.exchange(server_private_key.public_key())
    same_derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(
        same_shared_key)

    pub,priv =createAsymKeys(2048)

    f = open('Server_priv.pem', 'wb')
    f.write(priv.private_bytes(    encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption()))
    f.close()
    f = open('Server_pub.pem', 'wb')
    f.write(pub)
    f.close()
