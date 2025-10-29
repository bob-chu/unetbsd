import socket
import argparse
import time

def udp_server(host='0.0.0.0', port=12345):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((host, port))
    print(f"UDP server listening on {host}:{port}", flush=True)

    while True:
        data, addr = server_sock.recvfrom(1024)
        print(f"Server received {len(data)} bytes from {addr}: {data.decode('utf-8')}", flush=True)
        server_sock.sendto(data, addr)
        print(f"Server sent {len(data)} bytes back to {addr}", flush=True)

def udp_client(host='192.168.1.2', port=12345, count=10):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for i in range(count):
        message = f"Hello, UDP message {i+1}"
        client_sock.sendto(message.encode('utf-8'), (host, port))
        print(f"Client sent: {message}", flush=True)
        
        data, addr = client_sock.recvfrom(1024)
        print(f"Client received {len(data)} bytes from {addr}: {data.decode('utf-8')}", flush=True)
        time.sleep(0.1)

    client_sock.close()
    print("Test completed", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP Server/Client Script")
    parser.add_argument('mode', choices=['server', 'client'], help="Run as 'server' or 'client'")
    parser.add_argument('--host', default='192.168.1.2', help="Host IP address")
    parser.add_argument('--port', type=int, default=12345, help="Port number")
    parser.add_argument('--count', type=int, default=10, help="Number of messages to send (client mode)")
    args = parser.parse_args()

    if args.mode == 'server':
        udp_server(host='0.0.0.0', port=args.port)
    elif args.mode == 'client':
        udp_client(host=args.host, port=args.port, count=args.count)