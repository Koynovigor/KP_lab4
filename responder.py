import hashlib
import hmac
import socket
from os import urandom

from Crypto.Cipher import DES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers

from initiator import ID_I

# Параметры из RFC 2412
p_hex = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
g = 2
parameters = DHParameterNumbers(p_hex, g).parameters(default_backend())

# Генерация ключей
private_key = parameters.generate_private_key()
public_key = private_key.public_key()

# Вычисляем секретный параметр y
y = int.from_bytes(urandom(32), "big")  # Секретное случайное число
g_y = pow(g, y, p_hex)  # Вычисляем g^y mod p

# Публичный ключ для передачи
public_key_bytes = g_y.to_bytes((g_y.bit_length() + 7) // 8, "big")


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
Nr = urandom(16)  # Одноразовый номер респондента
ID_R = b"Responder-ID"
OK_KEYX = b"OK_KEYX"
EHAS = b"AES|SHA-256|HMAC"


def server_program():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(1)
    print("Server listening on port 5000...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # 1. Получаем начальный запрос от инициатора (0, 0, OK_KEYX)
    data = conn.recv(1024)
    if data[2:] != OK_KEYX:
        print("Authentication failed: Invalid OK_KEYX")
        conn.close()
        return

    # Отправляем CKY-R и OK_KEYX
    CKY_R = urandom(8)
    conn.send(CKY_R + OK_KEYX)

    # 2. Получаем CKY-I, CKY-R, OK_KEYX, GRP, g^x, EHAO
    data = conn.recv(2048)
    CKY_I = data[:8]
    received_CKY_R = data[8:16]
    if received_CKY_R != CKY_R:
        print("Authentication failed: CKY-R mismatch")
        conn.close()
        return

    client_public_key_length = int.from_bytes(data[16:20], 'big')
    client_public_key_bytes = data[20:20 + client_public_key_length]
    EHAO = data[20 + client_public_key_length:]

    # Выводим доступные алгоритмы для отладки
    print("EHAO received from initiator:", EHAO.decode())

    try:
        client_public_key = serialization.load_pem_public_key(
            client_public_key_bytes, backend=default_backend()
        )
    except ValueError:
        print("Authentication failed: Invalid public key from initiator")
        conn.close()
        return

    # Вычисляем общий секретный ключ
    shared_key = private_key.exchange(client_public_key)

    # Отправляем CKY-R, CKY-I, OK_KEYX, GRP, g^y, EHAS
    message = len(public_key_bytes).to_bytes(4, 'big') + public_key_bytes + EHAS
    conn.send(message)

    # 3. Получаем CKY-I, CKY-R, OK_KEYX, GRP, g^x, IDP*, ID(I), ID(R), E{Ni}Kr
    data = conn.recv(2048)
    encrypted_Ni = data[-16:]
    des_key = shared_key[:8]
    des = DES.new(des_key, DES.MODE_ECB)
    Ni = des.decrypt(encrypted_Ni)

    # 4. Отправляем CKY-R, CKY-I, OK_KEYX, GRP, 0, 0, IDP, E{Nr, Ni}Ki, ID(R), ID(I), prf(...)
    encrypted_Nr_Ni = des.encrypt(pad(Nr + Ni))
    Kir = prf(b'\x00', Ni + Nr)
    server_prf = prf(Kir, ID_R + ID_I + public_key_bytes + EHAS)
    response = (
            CKY_R + CKY_I + OK_KEYX + b"0" + b"0" + b"IDP" + encrypted_Nr_Ni + ID_R + ID_I + server_prf
    )
    conn.send(response)

    # 5. Получаем финальное сообщение: CKY-I, CKY-R, OK_KEYX, GRP, 0, 0, IDP, prf(...)
    data = conn.recv(2048)
    client_prf = data[-32:]
    expected_prf = prf(Kir, ID_I + ID_R + public_key_bytes + EHAS)

    if client_prf != expected_prf:
        print("Authentication failed: Client PRF mismatch")
        conn.close()
        return

    print("Authentication successful!")
    print("Session key:", Kir)

    conn.close()


if __name__ == "__main__":
    server_program()
