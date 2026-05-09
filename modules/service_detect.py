import socket
from colorama import Fore, Style, init

init(autoreset=True)

def service_detect(target, ports=None, verbose=False):
    print(Fore.CYAN + "[SERVICE DETECTION STARTED]")
    if ports is None:
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432]

    services = {
        21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL'
    }

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = services.get(port, 'Unknown')
                print(Fore.GREEN + f"[SERVICE] Port {port}: {service}")
            sock.close()
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] Port {port} - {e}")

    print(Fore.CYAN + "[SERVICE DETECTION COMPLETED]")