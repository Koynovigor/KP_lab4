import os
import socket
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.backends import default_backend

# Генерация параметров DH и ключей для сервера
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
private_key = parameters.generate_private_key()
public_key = private_key.public_key()

# Серийный идентификатор и ключ для передачи
server_id = os.urandom(16)
param_bytes = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)
server_public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Настройка сервера
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5000))
server_socket.listen(1)
print("Сервер ожидает подключение клиента...")
conn, addr = server_socket.accept()
print(f"Подключен клиент: {addr}")

# Форматируем и отправляем данные с указанием длины каждого блока
conn.sendall(len(server_id).to_bytes(2, 'big') + server_id)
conn.sendall(len(param_bytes).to_bytes(4, 'big') + param_bytes)
conn.sendall(len(server_public_key_bytes).to_bytes(4, 'big') + server_public_key_bytes)

# Получаем данные от клиента
data = conn.recv(1024)
client_id = data[:16]
client_public_key_bytes = data[16:]

# Загружаем публичный ключ клиента
try:
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes, backend=default_backend())
except ValueError as e:
    print("Ошибка при загрузке публичного ключа клиента:", e)
    conn.close()
    server_socket.close()
    exit()

# Вычисляем общий ключ с клиентом
shared_key = private_key.exchange(client_public_key)

# Генерация общего секрета
kdf = ConcatKDFHash(
    algorithm=hashes.SHA256(),
    length=32,
    otherinfo=b"handshake data",
    backend=default_backend()
)
shared_secret = kdf.derive(shared_key)

# Получаем подтверждение от клиента
client_confirmation = conn.recv(1024)
hmac_key = hmac.new(shared_secret, b"client_confirmation", hashlib.sha256).digest()
if hmac.compare_digest(hmac_key, client_confirmation):
    print("Сервер успешно прошел аутентификацию с клиентом.\n", shared_secret)
    # Отправляем подтверждение клиенту
    conn.sendall(hmac_key)
else:
    print("Аутентификация сервера не удалась.")

conn.close()
server_socket.close()
