from scanner import PortScanner
import argparse
from tqdm import tqdm

def main():

    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("target", help="Target IP or network (e.g., 192.168.1.0/24)")
    parser.add_argument("--sweep", "-s", action="store_true", help="Perform sweep scan only")
    parser.add_argument("--port-scan", "-p", action="store_true", help="Perform port scan only")
    parser.add_argument("--sweep-port", "-sp", action="store_true", help="Perform sweep and scan ports on live hosts")
    parser.add_argument("--protocol", "-pr", choices=["TCP", "UDP"], default="TCP", help="Choose between TCP or UDP")
    parser.add_argument("--threads", "-t", type=int, default=100, help="Number of threads")
    parser.add_argument("--ports", "-P", nargs=2, type=int, default=(1, 1024), help="Port range (start end)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    scanner = PortScanner(args.target, port_range=tuple(
        args.ports), num_threads=args.threads, protocol=args.protocol, verbose=args.verbose)
    scanner.run(sweep=args.sweep, port_scan=args.port_scan,
                sweep_and_scan=args.sweep_port)


if __name__ == "__main__":
    main()
