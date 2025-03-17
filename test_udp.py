import socket
import threading
import time

# UDP 服务器
def udp_server(host='127.0.0.1', port=12345):
    # 创建 UDP socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 绑定地址
    server_sock.bind((host, port))
    print(f"UDP server listening on {host}:{port}")

    while True:
        # 接收数据和发送方地址
        data, addr = server_sock.recvfrom(1024)  # 缓冲区大小 1024 字节
        print(f"Server received {len(data)} bytes from {addr}: {data.decode('utf-8')}")
        
        # 回显数据
        server_sock.sendto(data, addr)
        print(f"Server sent {len(data)} bytes back to {addr}")

# UDP 客户端
def udp_client(host='192.168.1.2', port=12345):
    # 创建 UDP socket
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 发送消息
    message = "Hello, UDP!"
    client_sock.sendto(message.encode('utf-8'), (host, port))
    print(f"Client sent: {message}:")
    print(b'Hello, UDP!')

    # 接收回复
    data, addr = client_sock.recvfrom(1024)
    print(f"Client received {len(data)} bytes from {addr}: {data.decode('utf-8')}")

    client_sock.close()

# 主函数
if __name__ == "__main__":
    # 启动服务器线程
    #server_thread = threading.Thread(target=udp_server, args=('192.168.1.2', 12345))
    #server_thread.daemon = True  # 设置为守护线程，主程序退出时自动结束
    #server_thread.start()

    # 等待服务器启动
    time.sleep(1)
    max_count = 10000;
    count = 0
    # 运行客户端
    while True:
        udp_client('192.168.1.2', 12345)
        time.sleep(0.01)
        count += 1
        if count >= max_count:
            break

    # 保持主线程运行以观察服务器输出
    print("Test completed")
