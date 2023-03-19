import socket
import base64
import subprocess

# 读取待发送的 ELF 文件
with open('./fuzz-demo/demo4', 'rb') as f:
    elf_data = f.read()

# base64 编码 ELF 文件数据
elf_base64 = base64.b64encode(elf_data).decode()

# 创建 TCP 服务器套接字
host = ''  # 监听所有可用接口
port = 12345  # 监听端口
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(10)  # 最大连接数为 10

print(f'TCP server is listening on {host}:{port}...')

while True:
    # 接受客户端连接请求
    client_socket, client_address = server_socket.accept()
    print(f'Accepted connection from {client_address}')

    try:
        # 发送 ELF 文件数据
        client_socket.sendall(elf_base64.encode() + b'\n')
        print('ELF file has been sent successfully.')

        # 执行 ELF 文件，并将 stdin 和 stdout 重定向到客户端套接字
        process = subprocess.Popen(
            ['./fuzz-demo/demo4'],
            stdin=client_socket,
            stdout=client_socket,
            stderr=subprocess.PIPE)
        # process.wait()
        print('ELF file has been executed.')
    except Exception as e:
        print(e)
        print('Failed to send ELF file.')

    # 关闭客户端连接
    client_socket.close()
