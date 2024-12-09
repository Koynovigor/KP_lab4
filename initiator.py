import hashlib
import hmac
import socket
from os import urandom

from Crypto.Cipher import DES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers

# Параметры группы DH из RFC 2412
p_hex = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
g = 2
parameters = DHParameterNumbers(p_hex, g).parameters()

# Генерация ключей
private_key = parameters.generate_private_key()
public_key = private_key.public_key()


# Вспомогательные функции
def pad(text):
    """Добавление выравнивания для блока данных."""
    while len(text) % 8 != 0:
        text += b" "
    return text


def prf(key, data):
    """Псевдослучайная функция (PRF) с использованием HMAC и SHA-256."""
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()


# Идентификаторы и параметры
Ni = urandom(16)  # Одноразовый номер инициатора
ID_I = b"Initiator-ID"
ID_R = b"Responder-ID"
OK_KEYX = b"OK_KEYX"
EHAO = b"AES|SHA-256|HMAC"


def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5000))

    # Шаг 1: Отправляем начальный запрос (0, 0, OK_KEYX)
    client_socket.send(b"0" + b"0" + OK_KEYX)

    # Шаг 2: Получаем 0, CKY-R, OK_KEYX от сервера
    data = client_socket.recv(1024)
    if data[0:1] != b"0" or data[9:] != OK_KEYX:
        print("Authentication failed: Invalid response")
        client_socket.close()
        return
    CKY_R = data[1:9]  # Извлекаем CKY-R

    # Шаг 3: Отправляем CKY-I, CKY-R, OK_KEYX, GRP, g^x, EHAO
    CKY_I = urandom(8)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(CKY_I + CKY_R + OK_KEYX + public_key_bytes + EHAO)

    # Шаг 4: Получаем CKY-R, CKY-I, OK_KEYX, GRP, g^y, EHAS
    data = client_socket.recv(2048)
    received_CKY_R = data[:8]
    received_CKY_I = data[8:16]
    if received_CKY_R != CKY_R or received_CKY_I != CKY_I:
        print("Authentication failed: CKY mismatch")
        client_socket.close()
        return
    server_public_key = serialization.load_pem_public_key(data[16:-len(EHAO)])
    EHAS = data[-len(EHAO):]

    # Вычисляем общий секретный ключ
    shared_key = private_key.exchange(server_public_key)

    # Шаг 5: Отправляем CKY-I, CKY-R, OK_KEYX, GRP, g^x, IDP*, ID(I), ID(R), E{Ni}Kr
    des_key = shared_key[:8]
    des = DES.new(des_key, DES.MODE_ECB)
    encrypted_Ni = des.encrypt(pad(Ni))
    client_socket.send(CKY_I + CKY_R + OK_KEYX + public_key_bytes + b"IDP" + ID_I + ID_R + encrypted_Ni)

    # Шаг 6: Получаем CKY-R, CKY-I, OK_KEYX, GRP, 0, 0, IDP, E{Nr, Ni}Ki, ID(R), ID(I), prf(...)
    data = client_socket.recv(2048)
    received_CKY_R = data[:8]
    received_CKY_I = data[8:16]
    if received_CKY_R != CKY_R or received_CKY_I != CKY_I:
        print("Authentication failed: CKY mismatch")
        client_socket.close()
        return
    encrypted_Nr_Ni = data[-64:-32]
    Nr_Ni = des.decrypt(encrypted_Nr_Ni)
    Nr = Nr_Ni[:16]
    Ni_received = Nr_Ni[16:]
    if Ni_received != Ni:
        print("Authentication failed: Ni mismatch")
        client_socket.close()
        return

    # Проверяем PRF от сервера
    Kir = prf(b'\x00', Ni + Nr)
    server_prf = data[-32:]
    expected_prf = prf(Kir, ID_R + ID_I + public_key_bytes + EHAS)
    if server_prf != expected_prf:
        print("Authentication failed: Server PRF mismatch")
        client_socket.close()
        return

    # Шаг 7: Отправляем CKY-I, CKY-R, OK_KEYX, GRP, 0, 0, IDP, prf(...)
    client_prf = prf(Kir, ID_I + ID_R + public_key_bytes + EHAS)
    client_socket.send(CKY_I + CKY_R + OK_KEYX + b"0" + b"0" + b"IDP" + client_prf)

    print("Authentication successful!")
    print("Session key:", Kir)
    client_socket.close()


if __name__ == "__main__":
    client_program()
