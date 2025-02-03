from scanner import PortScanner


def main():
    scanner = PortScanner('192.168.1.1', num_threads=100, protocol="TCP")
    scanner.run()


if __name__ == "__main__":
    main()
