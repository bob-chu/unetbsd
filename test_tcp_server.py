import socket

def tcp_echo_server_ipv6(host='::', port=12345):
    """
    Start a TCP echo server that listens for IPv6 connections and echoes back any received data.

    Args:
        host (str): The IPv6 host address to bind to (default '::' for all IPv6 interfaces)
        port (int): The port to listen on (default 12345)
    """
    # Create an IPv6 TCP/IP socket
    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    # set SOL_REUSEADDR
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to the port
    server_address = (host, port, 0, 0)  # For IPv6, the address is a tuple of (host, port, flowinfo, scopeid)
    print(f"Starting up on {server_address}")
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(1)

    while True:
        # Wait for a connection
        print("Waiting for a connection...")
        connection, client_address = server_socket.accept()
        try:
            print(f"Connection from {client_address}")

            while True:
                # Receive the data in small chunks
                data = connection.recv(2048)
                if data:
                    print(f"Received: {data.decode('utf-8')}")
                    # Send the data back
                    connection.sendall(data)
                    print(f"Sent back: {data.decode('utf-8')}")
                else:
                    # No more data from client
                    print(f"No more data from {client_address}")
                    break

        finally:
            # Clean up the connection
            connection.close()
            print(f"Closed connection with {client_address}")

if __name__ == "__main__":
    tcp_echo_server_ipv6()
