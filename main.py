import argparse
import concurrent.futures
import signal
import socket
import sys
import logging

# Constantes
MAX_THREADS = 200

# Variável para sinalizar que a varredura deve ser interrompida.
cancel_scan = False

def setup_logger(output_file, silent):
    logger = logging.getLogger('PortScanner')
    logger.setLevel(logging.INFO)

    # Create file handler
    handler = logging.FileHandler(output_file)
    handler.setLevel(logging.INFO)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(handler)
    if not silent:
        logger.addHandler(console_handler)

    return logger

def get_service(port, protocol):
    try:
        return socket.getservbyport(port, protocol)
    except Exception:
        return "Unknown"

def scan_port(ip, port, udp, timeout=1):
    protocol = 'udp' if udp else 'tcp'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return f'Port {port} ({get_service(port, protocol)}) is open'
        except:
            return None

def signal_handler(signal, frame):
    global cancel_scan
    print("\nScan is being cancelled...")
    cancel_scan = True
    sys.exit(0)

def main():
    ips = ["192.168.1.1"]
    start_port = 1
    end_port = 1024
    udp = False
    silent = False
    output_file = 'portscan.log'

    logger = setup_logger(output_file, silent)

    scan = scan_port

    signal.signal(signal.SIGINT, signal_handler)

    ports = [port for port in range(start_port, end_port + 1)]

    for ip in ips:
        try:
            ip = socket.gethostbyname(ip)  # Resolve hostname to IP
        except socket.gaierror:
            logger.error(f'Failed to resolve {ip}')
            continue

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_port = {executor.submit(scan, ip, port, udp): port for port in ports}

            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                except Exception as e:
                    logger.error(f"Error scanning port {port} at {ip}: {str(e)}")
                else:
                    if result:
                        logger.info(result)

        print("Scanning complete for ", ip)

if __name__ == "__main__":
    main()
