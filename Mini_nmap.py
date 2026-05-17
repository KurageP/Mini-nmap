"""Mini Nmap - a simple port scanner built from scratch."""
print("Script is starting...")
import socket
import threading
def scan_port(host, port):
    """try to connect to host::port. return true if open and false if clossed"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) #wait max 1 second per port

    try:
        s.connect((host, port))
        return True #connction worked
    except (socket.error, ConnectionRefusedError, OSError):
        return False #connectionfailed
    finally:
        s.close() #always close the socket, no matter what

lock = threading.Lock()

def scan_and_report(host, port):
    try:
        service = socket.getservbyport(port)
    except:
        service = "unknown"
    if scan_port(host, port):
        with lock:
            print(f"Port {port} is OPEN and running {service}  ")
            with open("filename.txt", "a") as f:
                f.write(f"Port {port} is OPEN and running {service}\n")

if __name__ == "__main__":
    host= input("Enter Host: ")
    start_port = int(input("Enter start port: ")) 
    end_port = int(input("enter end port: "))
    for port in range(start_port, end_port + 1):
        print(f"Scanning port {port}...") #temporary
        threading.Thread(target=scan_and_report, args=(host, port)).start()
        
