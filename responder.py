import hashlib
import hmac
import socket
from os import urandom

from Crypto.Cipher import DES

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

# Секретный параметр респондента (y) и вычисление g^y
y = int.from_bytes(urandom(32), "big")  # Случайное число для y
g_y = pow(g, y, p_hex)  # Вычисляем g^y mod p


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


# Идентификаторы
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

    # Шаг 1: Получаем начальный запрос
    data = conn.recv(1024)
    if data[:2] != b"00" or data[2:] != OK_KEYX:
        print("Authentication failed: Invalid OK_KEYX")
        conn.close()
        return

    # Шаг 2: Отправляем 0, CKY-R, OK_KEYX
    CKY_R = urandom(8)
    conn.send(b"0" + CKY_R + OK_KEYX)

    # Шаг 3: Получаем CKY-I, CKY-R, OK_KEYX, GRP, g^x, EHAO
    data = conn.recv(2048)
    CKY_I = data[:8]
    received_CKY_R = data[8:16]
    if received_CKY_R != CKY_R:
        print("Authentication failed: CKY-R mismatch")
        conn.close()
        return
    g_x_bytes = data[23:-len(EHAS)]
    g_x = int.from_bytes(g_x_bytes, "big")  # Преобразуем g^x из байтов
    EHAO = data[-len(EHAS):]

    # Вычисляем общий секретный ключ: g^(xy) mod p
    shared_key = pow(g_x, y, p_hex)

    # Шаг 4: Отправляем CKY-R, CKY-I, OK_KEYX, GRP, g^y, EHAS
    g_y_bytes = g_y.to_bytes((g_y.bit_length() + 7) // 8, "big")  # Преобразуем g^y в байты
    conn.send(CKY_R + CKY_I + OK_KEYX + g_y_bytes + EHAS)



    # Шаг 5: Получаем CKY-I, CKY-R, OK_KEYX, GRP, g^x, IDP*, ID(I), ID(R), E{Ni}Kr
    data = conn.recv(2048)
    encrypted_Ni = data[-16:]
    key_size = (p_hex.bit_length() + 7) // 8  # Длина ключа в байтах
    des_key = shared_key.to_bytes(key_size, "big")[:8]
    des = DES.new(des_key, DES.MODE_ECB)
    Ni = des.decrypt(encrypted_Ni)

    # Шаг 6: Отправляем CKY-R, CKY-I, OK_KEYX, GRP, 0, 0, IDP, E{Nr, Ni}Ki, ID(R), ID(I), prf(...)
    encrypted_Nr_Ni = des.encrypt(pad(Nr + Ni))
    Kir = prf(b'\x00', Ni + Nr)
    server_prf = prf(Kir, ID_R + b"Initiator-ID" + g_y_bytes + EHAS)
    conn.send(CKY_R + CKY_I + OK_KEYX + b"0" + b"0" + b"IDP" + encrypted_Nr_Ni + ID_R + b"Initiator-ID" + server_prf)

    # Шаг 7: Получаем финальное подтверждение
    data = conn.recv(2048)
    client_prf = data[-32:]
    expected_prf = prf(Kir, b"Initiator-ID" + ID_R + g_x_bytes + EHAS)
    if client_prf != expected_prf:
        print("Authentication failed: Client PRF mismatch")
        conn.close()
        return

    print("Authentication successful!")
    print("Session key:", Kir)
    conn.close()


if __name__ == "__main__":
    server_program()
