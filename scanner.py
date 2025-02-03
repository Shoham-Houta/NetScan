import socket
import threading
import queue
import subprocess
import platform
import re


class PortScanner:
    def __init__(self, target, port_range=(1, 1024), num_threads=50, protocol="TCP"):
        self.target = target
        self.port_range = port_range
        self.num_threads = num_threads
        self.protocol = protocol.upper()
        self.port_queue = queue.Queue()
        self.open_ports = []
        self.filtered_ports = []
        self.closed_ports = []
        self.live_hosts = []

    def scan_tcp_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((self.target, port))
            print(f"[+] TCP Port {port} is OPEN")
            self.open_ports.append((port, socket.getservbyport(port)))
        except socket.timeout:
            print(f"[!] TCP Port {port} is FILTERED (timeout)")
            self.filtered_ports.append((port, socket.getservbyport(port)))
        except ConnectionRefusedError:
            print(f"[-] TCP Port {port} is CLOSED")
            self.closed_ports.append(port)
        except OSError as e:
            if e.errno == 113:
                print(f"[!] TCP Port {port} is FILTERED (no route to host)")
                self.filtered_ports.append(port)
        finally:
            s.close()

    def sweep_scan(self, network):
        print(f"Scanning network: {network}.0/24")
        param = "-n" if platform.system().lower() == "windows" else "-c"

        def ping_host(ip):
            command = ["ping", param, "1", ip]
            result = subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                print(f"[+] Host {ip} is ONLINE")
                self.live_hosts.append(ip)
            else:
                print(f"[-] Host {ip} is OFFLINE or FILTERED")

        threads = []
        for i in range(1, 255):
            ip = f"{network}.{i}"
            thread = threading.Thread(target=ping_host, args=(ip,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    def scan_udp_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(b"test", (self.target, port))
            data, _ = s.recvfrom(1024)
            print(f"[+] UDP Port {port} is OPEN")
            self.open_ports.append(port)
        except socket.timeout:
            print(f"[!] UDP Port {port} may be OPEN or FILTERED (no response)")
            self.filtered_ports.append(port)
        except OSError as e:
            if e.errno == 113:
                print(f"[!] UDP Port {port} is FILTERED (no route to host)")
                self.filtered_ports.append(port)
            else:
                print(f"[-] UDP Port {port} is CLOSED")
                self.closed_ports.append(port)
        finally:
            s.close()

    def worker(self):
        while not self.port_queue.empty():
            port = self.port_queue.get()
            if self.protocol == "TCP":
                self.scan_tcp_port(port)
            elif self.protocol == "UDP":
                self.scan_udp_port(port)
            self.port_queue.task_done()

    def run(self):
        print(
            f"Scanning {self.target} from port {self.port_range[0]} to {self.port_range[1]} using {self.protocol}...")

        # If target is a network (e.g., 192.168.1.0), perform sweep scan
        if re.match(r"\d+\.\d+\.\d+\.0", self.target):
            network = self.target.rsplit('.', 1)[0]  # Extract network portion
            self.sweep_scan(network)
            print(f"Live Hosts: {self.live_hosts}")
            return  # Skip port scan if it's a sweep

        # Fill the queue with ports to scan
        for port in range(self.port_range[0], self.port_range[1] + 1):
            self.port_queue.put(port)

        # Start worker threads
        threads = []
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        print("\nScan complete.")
        print(f"Open Ports: {self.open_ports}")
        print(f"Filtered Ports: {self.filtered_ports}")
