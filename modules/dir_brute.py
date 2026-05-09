import requests
from colorama import Fore, Style, init
import threading
from queue import Queue
import time
import os

init(autoreset=True)

class DirBrute:
    def __init__(self, target, wordlist_path=None, threads=10, extensions=None, verbose=False):
        self.target = target.rstrip('/')
        self.wordlist_path = wordlist_path or os.path.join(os.path.dirname(__file__), 'wordlist.txt')
        self.threads = threads
        self.extensions = extensions or ['.php', '.html', '.txt', '.bak', '.old']
        self.verbose = verbose
        self.found_dirs = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def check_directory(self, path):
        urls = [f"{self.target}/{path}"]
        for ext in self.extensions:
            urls.append(f"{self.target}/{path}{ext}")

        for url in urls:
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403, 401]:
                    self.found_dirs.append((url, response.status_code))
                    print(Fore.GREEN + f"[FOUND] {url} - {response.status_code}")
                elif self.verbose and response.status_code != 404:
                    print(Fore.YELLOW + f"[INFO] {url} - {response.status_code}")
            except requests.RequestException as e:
                if self.verbose:
                    print(Fore.RED + f"[ERROR] {url} - {e}")

    def brute_force(self):
        if not os.path.exists(self.wordlist_path):
            print(Fore.RED + f"Wordlist not found: {self.wordlist_path}")
            return

        with open(self.wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]

        queue = Queue()
        for word in words:
            queue.put(word)

        def worker():
            while not queue.empty():
                path = queue.get()
                self.check_directory(path)
                queue.task_done()

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print(Fore.CYAN + f"\n[COMPLETED] Found {len(self.found_dirs)} directories/files")

def dir_brute(target, wordlist=None, threads=10, extensions=None, verbose=False):
    brute = DirBrute(target, wordlist, threads, extensions, verbose)
    brute.brute_force()