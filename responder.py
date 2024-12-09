from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from os import urandom
import socket
from Crypto.Cipher import DES

# Параметры группы и алгоритмы
GRP = {
    "name": "Group-1", 
    "generator": b'1234567812345678', 
    "g_y": urandom(32)
}
EHAS = {"encryption": "AES", "hashing": "SHA-256", "authentication": "RSA"}  # Выбранные сервером алгоритмы
Nr = urandom(16)  # Одноразовый номер ответчика
ID_R = b"Responder-ID"  # Идентификатор ответчика
OK_KEYX = b"OK_KEYX"  # Константа протокола для подтверждения обмена ключами

# Функция псевдослучайного генератора prf
def prf(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def pad(text):
    while len(text) % 8 != 0:
        text += b' '
    return text

# Серверная часть
def server_program():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(1)
    print("Server listening on port 5000...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # 1. Сервер получает первый запрос и отправляет cookie (CKY-R) и OK_KEYX
    data = conn.recv(1024)
    if data[2:] != OK_KEYX:
        conn.close()
        print("Authentication failed on server: NO OK_KEYX")
    CKY_R = urandom(8) # 64 бита
    conn.send(b"0" + CKY_R + OK_KEYX)

    # 2. Сервер получает от клиента CKY-I, CKY-R, OK_KEYX, GRP, g^x, EHAO
    data = conn.recv(1024)
    CKY_I = data[:8]
    received_CKY_R = data[8:16]
    g_x = data[39:71]

    # Проверка на соответствие CKY_R и полученного значения
    if received_CKY_R != CKY_R:
        conn.close()
        print("Authentication failed on server: received_CKY_R != CKY_R")

    # 3. Сервер отвечает с CKY-R, CKY-I, OK_KEYX, GRP, g^y, EHAS
    response_payload = CKY_R + CKY_I + OK_KEYX + GRP["generator"] + GRP["g_y"] + EHAS["encryption"].encode()
    conn.send(response_payload)

    # 4. Сервер получает финальный запрос с идентификаторами и зашифрованным Ni
    data = conn.recv(1024)
    g_y_key = GRP["g_y"][0:8]
    des = DES.new(g_y_key, DES.MODE_ECB)
    Ni_enc = data[98:]
    Ni = des.decrypt(Ni_enc)
    ID_I = data[74:86]

    Kir = prf(b'\x00', Ni + Nr)

    # Отправка сообщения клиенту
    verification_payload = CKY_R + CKY_I + OK_KEYX + GRP["generator"] + b"0" + b"0" + b"IDP"
    enc = des.encrypt(pad(Nr + Ni)) + ID_R + ID_I
    prf_resp = prf(Kir, ID_R + ID_I + GRP["generator"] + GRP["g_y"] + g_x + EHAS["encryption"].encode())
    conn.send(verification_payload + enc + prf_resp)

    data = conn.recv(1024)
    prf1 = prf(Kir, ID_I + ID_R + GRP["generator"] + g_x + GRP["g_y"] + EHAS["encryption"].encode())
    prf1_resp = data[44:]

    if prf1 == prf1_resp:
        conn.send(b'success')
        print("Server completed authentication")
        print("Session key: ", Kir)
    else:
        conn.close()
        print("Authentication failed on server: prf1")


    conn.close()
if __name__ == '__main__':
    server_program()
