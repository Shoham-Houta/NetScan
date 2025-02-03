import socket
import threading
import queue


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

    def scan_tcp_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((self.target, port))

            print(f"[+] TCP Port {port} is OPEN")
            self.open_ports.append((port, socket.getservbyport(port)))
            s.close()
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
            else:
                pass
        finally:
            s.close()

    def scan_udp_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(b"test", (self.target, port))  # sending a dummy packet
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
        # print(f"Closed Ports: {self.closed_ports}")
