# client.py
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from os import urandom
import socket
from Crypto.Cipher import DES

# Параметры группы и идентификаторы
GRP = {
    "name": "Group-1", 
    "generator": b'1234567812345678', 
    "g_x": urandom(32)
}

def pad(text):
    while len(text) % 8 != 0:
        text += b' '
    return text

Ni = urandom(16)  # Одноразовый номер инициатора
EHAS = {"encryption": "AES", "hashing": "SHA-256", "authentication": "RSA"}
ID_R = b"Responder-ID"  # Идентификатор ответчика
ID_I = b"Initiator-ID"  # Идентификатор инициатора
OK_KEYX = b"OK_KEYX"  # Константа протокола для подтверждения обмена ключами

# Функция псевдослучайного генератора prf
def prf(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Клиентская часть
def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5000))

    # 1. Клиент отправляет серверу начальный запрос (0, 0, OK_KEYX)
    client_socket.send(b"0" + b"0" + OK_KEYX)

    # 2. Клиент получает ответ сервера: CKY-R и OK_KEYX
    data = client_socket.recv(1024)
    CKY_R = data[1:9]
    if data[9:] != OK_KEYX:
        client_socket.close()
        print("Authentication failed on client: NO OK_KEYX")

    # 3. Клиент отправляет серверу CKY-I, CKY-R, OK_KEYX, GRP, g^x, EHAO
    CKY_I = urandom(8) # 64 бита
    EHAO = {"encryption": "AES", "hashing": "SHA-256", "authentication": "RSA"}  # Параметры алгоритма клиента
    client_socket.send(CKY_I + CKY_R + OK_KEYX + GRP["generator"] + GRP["g_x"] + EHAO["encryption"].encode())

    # 4. Клиент получает ответ сервера с CKY-R, CKY-I, OK_KEYX, GRP, g^y и EHAS
    data = client_socket.recv(1024)
    received_CKY_I = data[8:16]
    g_y = data[39:71]
    g_y_key = data[39:47]

    # Проверка на соответствие CKY_R и полученного значения
    if received_CKY_I != CKY_I:
        client_socket.close()
        print("Authentication failed on client: received_CKY_I != CKY_I")
    des = DES.new(g_y_key, DES.MODE_ECB)

    # 5. Клиент отправляет серверу CKY-I, CKY-R, OK_KEYX, GRP, g^x, IDP, ID(I), ID(R), E{Ni}Kr
    client_socket.send(CKY_I + CKY_R + OK_KEYX + GRP["generator"] + GRP["g_x"] + b"IDP" + ID_I + ID_R + des.encrypt(pad(Ni)))

    # 6. Клиент получает ответ сервера с подтверждением
    data = client_socket.recv(1024)
    Nr_Ni = des.decrypt(data[44:76])
    Nr = Nr_Ni[:16]
    Ni_recv = Nr_Ni[16:]
    if Ni_recv != Ni:
        client_socket.close()
        print("Authentication failed on client: Ni_recv != Ni")

    Kir = prf(b'\x00', Ni + Nr)
    prf_resp = data[100:]
    if prf_resp != prf(Kir, ID_R + ID_I + GRP["generator"] + g_y + GRP["g_x"] + EHAS["encryption"].encode()):
        client_socket.close()
        print("Authentication failed on client: prf_resp")

    resp = CKY_I + CKY_R + OK_KEYX + GRP["generator"] + b"0" + b"0" + b"IDP"
    prf1 = prf(Kir, ID_I + ID_R + GRP["generator"] + GRP["g_x"] + g_y + EHAS["encryption"].encode())
    client_socket.send(resp + prf1)

    data = client_socket.recv(1024)
    if data == b'success':
        print("Authentication process completed")
        print("Session key: ", Kir)
    else: 
        client_socket.close()
        print("Authentication failed on client: prf_resp1")
    client_socket.close()

if __name__ == '__main__':
    client_program()