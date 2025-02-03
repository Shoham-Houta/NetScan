import socket
import threading
import queue
import subprocess
import platform
from ipaddress import ip_address, ip_network
from tqdm import tqdm


class PortScanner:
    def __init__(self, target, port_range=(1, 1024), num_threads=100, protocol="TCP", verbose=False):
        self.target = target
        self.port_range = port_range
        self.num_threads = num_threads
        self.protocol = protocol.upper()
        self.verbose = verbose
        self.task_queue = queue.Queue()
        self.open_ports = []
        self.filtered_ports = []
        self.closed_ports = []
        self.live_hosts = []

    def log(self, message):
        if self.verbose:
            print(message)

    def scan_tcp_port(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, port))
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = 'Unknown'
            self.open_ports.append(
                {"ip": ip, "port": port, "service": service, "status": "OPEN"})
            self.log(f"[OPEN] {ip}:{port} ({service})")
        except socket.timeout:
            self.filtered_ports.append(
                {"ip": ip, "port": port, "status": "FILTERED (timeout)"})
        except ConnectionRefusedError:
            self.closed_ports.append(
                {"ip": ip, "port": port, "status": "CLOSED"})
        except OSError as e:
            if e.errno == 113:
                self.filtered_ports.append(
                    {"ip": ip, "port": port, "status": "FILTERED (no route to host)"})
        finally:
            s.close()

    def sweep_scan(self, network):
        print(f"Scanning network: {network}")
        param = "-n" if platform.system().lower() == "windows" else "-c"

        def ping_host(ip):
            command = ["ping", param, "1", str(ip)]
            result = subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                self.live_hosts.append(str(ip))
                self.log(f"[LIVE] Host {ip} is ONLINE")
 
        hosts = list(ip_network(network, strict=False).hosts())
        iterator = hosts if self.verbose else tqdm(
            hosts, desc="Sweep Progress")

        threads = []
        for ip in iterator:
            thread = threading.Thread(target=ping_host, args=(ip,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    def enqueue_tasks(self, hosts):
        for ip in hosts:
            for port in range(self.port_range[0], self.port_range[1] + 1):
                self.task_queue.put((ip, port))

    def scan_udp_port(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(b"test", (ip, port))
            data, _ = s.recvfrom(1024)
            self.open_ports.append({"ip": ip, "port": port, "status": "OPEN"})
            self.log(f"[OPEN] {ip}:{port} (UDP)")
        except socket.timeout:
            self.filtered_ports.append(
                {"ip": ip, "port": port, "status": "FILTERED (no response)"})
            self.log(f"[FILTERED] {ip}:{port} (no response)")
        except OSError as e:
            if e.errno == 113:
                self.filtered_ports.append(
                    {"ip": ip, "port": port, "status": "FILTERED (no route to host)"})
                self.log(f"[FILTERED] {ip}:{port} (no route to host)")
            else:
                self.closed_ports.append(
                    {"ip": ip, "port": port, "status": "CLOSED"})
                self.log(f"[CLOSED] {ip}:{port}")
        finally:
            s.close()

    def worker(self, progress_bar=None):
        while not self.task_queue.empty():
            ip, port = self.task_queue.get()
            if self.protocol == "TCP":
                self.scan_tcp_port(ip, port)
            elif self.protocol == "UDP":
                self.scan_udp_port(ip, port)
            self.task_queue.task_done()
            if progress_bar:
                progress_bar.update(1)

    def display_results(self):
        print("\n===== Scan Results =====")

        if self.live_hosts:
            print("Live Hosts:")
            for ip in sorted(self.live_hosts, key=lambda x: ip_address(x)):
                print(f"  - {ip} (ONLINE)")

        if self.open_ports:
            print("\nOpen Ports:")
            for port_info in sorted(self.open_ports, key=lambda x: (x['ip'], x['port'])):
                service = port_info.get('service', 'Unknown')
                print(
                    f"  - {port_info['ip']}: Port {port_info['port']} ({service}) is {port_info['status']}")

        if self.filtered_ports:
            print("\nFiltered Ports:")
            for port_info in sorted(self.filtered_ports, key=lambda x: (x['ip'], x['port'])):
                print(
                    f"  - {port_info['ip']}: Port {port_info['port']} is {port_info['status']}")

        # if self.closed_ports:
        #     print("\nClosed Ports:")
        #     for port_info in sorted(self.closed_ports, key=lambda x: (x['ip'], x['port'])):
        #         print(
        #             f"  - {port_info['ip']}: Port {port_info['port']} is {port_info['status']}")

    def run(self, sweep=False, port_scan=False, sweep_and_scan=False):
        try:
            network = ip_network(self.target, strict=False)
        except ValueError:
            network = None

        if sweep and network:
            self.sweep_scan(network)
            self.display_results()

        if port_scan:
            hosts = [str(host) for host in network.hosts()
                     ] if network else [self.target]
            self.enqueue_tasks(hosts)

        if sweep_and_scan and network:
            self.sweep_scan(network)
            self.enqueue_tasks(self.live_hosts)

        total_tasks = self.task_queue.qsize()
        progress_bar = tqdm(
            total=total_tasks, desc="Port Scan Progress") if not self.verbose else None

        threads = []
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self.worker, args=(progress_bar,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        if progress_bar:
            progress_bar.close()

        self.display_results()
