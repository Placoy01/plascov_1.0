import requests
from colorama import Fore, Style, init

init(autoreset=True)

def cms_scanner(target, verbose=False):
    print(Fore.CYAN + "[CMS SCANNER STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    cms_signatures = {
        'WordPress': ['/wp-admin/', '/wp-login.php', '/wp-content/'],
        'Joomla': ['/administrator/', '/components/', '/modules/'],
        'Drupal': ['/user/login', '/sites/default/', '/modules/'],
        'Magento': ['/admin/', '/downloader/', '/var/'],
        'PrestaShop': ['/admin/', '/modules/', '/themes/']
    }

    detected_cms = None

    for cms, paths in cms_signatures.items():
        for path in paths:
            try:
                url = f"{target.rstrip('/')}{path}"
                response = session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    detected_cms = cms
                    print(Fore.BLUE + f"[CMS DETECTED] {cms}")
                    break
            except:
                pass
        if detected_cms:
            break

    if not detected_cms:
        print(Fore.GREEN + "[CMS] No common CMS detected")

    print(Fore.CYAN + "[CMS SCANNER COMPLETED]")