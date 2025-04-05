import socket

def tcp_echo_client(server_address, message="12345", iterations=10000000):
    """

    Args:
        server_address (tuple): 服务器的地址，格式为 (host, port)。
        message (str): 要发送的消息。
        iterations (int): 执行连接、发送、接收和关闭操作的次数。
    """
    for i in range(iterations):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print(f"[{i+1}/{iterations}] Connecting to {server_address}...")
            client_socket.connect(server_address)
            print(f"[{i+1}/{iterations}] Connected.")

            encoded_message = message.encode('utf-8')
            print(f"[{i+1}/{iterations}] Sending: {message}")
            client_socket.sendall(encoded_message)

            data = client_socket.recv(1024)
            #decoded_message = data.decode('utf-8')
            print(f"[{i+1}/{iterations}] Received: {data}")

            client_socket.close()
            print(f"[{i+1}/{iterations}] Socket closed.")

        except ConnectionRefusedError:
            print(f"[{i+1}/{iterations}] Connection refused. Make sure the server is running at {server_address}.")
            break
        except Exception as e:
            print(f"[{i+1}/{iterations}] An error occurred: {e}")
            break

if __name__ == "__main__":
    server_host = '192.168.1.2'
    server_port = 80

    server_address = (server_host, server_port)

    tcp_echo_client(server_address)

    print("Finished executing the TCP echo client.")
