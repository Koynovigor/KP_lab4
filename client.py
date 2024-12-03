import os
import socket
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.backends import default_backend

# Подключение к серверу
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5000))

# Получаем длину и данные от сервера
server_id_length = int.from_bytes(client_socket.recv(2), 'big')
server_id = client_socket.recv(server_id_length)

param_length = int.from_bytes(client_socket.recv(4), 'big')
param_bytes = client_socket.recv(param_length)

server_public_key_length = int.from_bytes(client_socket.recv(4), 'big')
server_public_key_bytes = client_socket.recv(server_public_key_length)

# Загружаем параметры группы DH и создаем ключи для клиента
try:
    parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    client_public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
except ValueError as e:
    print("Ошибка при загрузке параметров группы DH:", e)
    client_socket.close()
    exit()

# Отправляем наш публичный ключ и идентификатор сервера
client_id = os.urandom(16)
client_socket.sendall(client_id + client_public_key_bytes)

# Загружаем публичный ключ сервера
try:
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())
except ValueError as e:
    print("Ошибка при загрузке публичного ключа сервера:", e)
    client_socket.close()
    exit()

# Вычисляем общий ключ с сервером
shared_key = private_key.exchange(server_public_key)

# Генерация общего секрета
kdf = ConcatKDFHash(
    algorithm=hashes.SHA256(),
    length=32,
    otherinfo=b"handshake data",
    backend=default_backend()
)
shared_secret = kdf.derive(shared_key)

# Отправляем подтверждение на сервер
hmac_key = hmac.new(shared_secret, b"client_confirmation", hashlib.sha256).digest()
client_socket.sendall(hmac_key)

# Получаем подтверждение от сервера
server_confirmation = client_socket.recv(1024)
if hmac.compare_digest(hmac_key, server_confirmation):
    print("Клиент успешно прошел аутентификацию с сервером.\n", shared_secret)
else:
    print("Аутентификация клиента не удалась.")

client_socket.close()
