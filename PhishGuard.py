import re
import requests
from bs4 import BeautifulSoup
import whois
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

def is_valid_url(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme and parsed_url.netloc:
            return True
        else:
            return False
    except Exception:
        return False

def contains_keywords(text, keywords):
    text = text.lower()
    for keyword in keywords:
        if keyword in text:
            return True
    return False

def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc.lower()

def get_subdomains(url):
    subdomains = re.findall(r"https?://([a-zA-Z0-9.-]+)\.", url)
    return subdomains

def get_path(url):
    parsed_url = urlparse(url)
    return parsed_url.path.lower()

def is_phishing(url):
    if not is_valid_url(url):
        return 0

    risk_score = 0

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        page_content = response.text.lower()

        phishing_keywords = ["secure", "login", "account", "verify", "update", "password", "bank", "paypal", "google", "airdrop", "crypto", "nft"]
        for keyword in phishing_keywords:
            if keyword in url.lower():
                risk_score += 5

        if len(url) > 100:
            risk_score += 10

        domain = get_domain(url)
        if "." not in domain:
            risk_score += 10

        phishing_page_keywords = ["password", "login", "bank", "credit card", "account", "social security"]
        if contains_keywords(page_content, phishing_page_keywords):
            risk_score += 5

        soup = BeautifulSoup(page_content, "html.parser")
        input_forms = soup.find_all("input")
        if len(input_forms) > 0:
            risk_score += 10

        domain_info = whois.whois(domain)
        if "creation_date" in domain_info and "expiration_date" in domain_info:
            creation_date = min(domain_info["creation_date"]) if isinstance(domain_info["creation_date"], list) else domain_info["creation_date"]
            expiration_date = min(domain_info["expiration_date"]) if isinstance(domain_info["expiration_date"], list) else domain_info["expiration_date"]
            if (expiration_date - creation_date).days < 365:
                risk_score += 10

        ip_address = socket.gethostbyname(domain)
        if is_ip_suspicious(ip_address):
            risk_score += 10

        if not is_valid_url_structure(url):
            risk_score += 10

        if is_js_redirect_present(page_content):
            risk_score += 5

        parent_domain = ".".join(domain.split(".")[-2:])
        parent_domain_info = whois.whois(parent_domain)
        if "creation_date" in parent_domain_info:
            parent_creation_date = min(parent_domain_info["creation_date"]) if isinstance(parent_domain_info["creation_date"], list) else parent_domain_info["creation_date"]
            if (creation_date - parent_creation_date).days < 365:
                risk_score += 10

        if not has_ssl_certificate(domain):
            risk_score += 10

        if is_http_headers_suspicious(url):
            risk_score += 5

        subdomains = get_subdomains(url)
        if subdomains:
            risk_score += 15

        if has_unusual_characters(url):
            risk_score += 5

        if has_expired_ssl_certificate(domain):
            risk_score += 20

        if is_url_shortened(url):
            risk_score += 10

        if is_high_risk_tld(url):
            risk_score += 15

        if detect_crypto_phishing(url):
            risk_score += 20

        return risk_score

    except requests.exceptions.RequestException:
        return 100

def is_ip_suspicious(ip_address):
    try:
        ip_info_url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(ip_info_url)
        data = response.json()
        if data.get("abuse"):
            return True
        if data.get("threat"):
            return True
        return False
    except Exception:
        return False

def is_valid_url_structure(url):
    try:
        parsed_url = urlparse(url)
        if all([parsed_url.scheme, parsed_url.netloc]):
            return True
        return False
    except Exception:
        return False

def is_js_redirect_present(page_content):
    try:
        if re.search(r"window.location\s*=\s*['\"]([^'\"]+)['\"]", page_content):
            return True
        return False
    except Exception:
        return False

def has_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except Exception:
        return False

def is_http_headers_suspicious(url):
    try:
        response = requests.head(url)
        headers = response.headers
        if "server" in headers and "apache" in headers["server"].lower():
            return True
        if "x-powered-by" in headers:
            return True
        return False
    except Exception:
        return False

def has_unusual_characters(url):
    try:
        if re.search(r"[^A-Za-z0-9:/\.-]", url):
            return True
        return False
    except Exception:
        return False

def has_expired_ssl_certificate(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = ssl.PEM_cert_to_DER_cert(cert)
        x509 = ssl.DER_cert_to_PEM_cert(x509)
        cert_info = ssl.cert_time_to_seconds(x509)
        expiration_date = cert_info["notAfter"]
        now = ssl.cert_time_to_seconds(ssl.cert_time())
        if expiration_date < now:
            return True
        return False
    except Exception:
        return False

def is_url_shortened(url):
    shortened_services = ["bit.ly", "tinyurl.com", "t.co"]
    for service in shortened_services:
        if service in url:
            return True
    return False

def is_high_risk_tld(url):
    high_risk_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    for tld in high_risk_tlds:
        if domain.endswith(tld):
            return True
    return False

def detect_crypto_phishing(url):
    crypto_keywords = ["wallet", "btc", "bitcoin", "eth", "ethereum", "crypto"]
    if contains_keywords(url, crypto_keywords):
        return True
    return False

def has_login_elements(page_content):
    login_elements = ["login", "username", "email", "password"]
    for element in login_elements:
        if re.search(rf'<[^>]*\b(name|id)\s*=\s*["\']{element}["\'][^>]*>', page_content):
            return True
    return False

def scan_url(url):
    scan_result = {
        "url": url,
        "risk_score": 0,
        "phishing_keywords": [],
        "length_risk": 0,
        "domain_risk": 0,
        "page_keywords_risk": 0,
        "input_forms_risk": 0,
        "domain_age_risk": 0,
        "ip_suspicious_risk": 0,
        "url_structure_risk": 0,
        "js_redirect_risk": 0,
        "parent_domain_age_risk": 0,
        "ssl_certificate_risk": 0,
        "http_headers_risk": 0,
        "subdomains_risk": 0,
        "unusual_characters_risk": 0,
        "expired_ssl_certificate_risk": 0,
        "url_shortened_risk": 0,
        "high_risk_tld_risk": 0,
        "crypto_phishing_risk": 0,
        "login_elements_risk": 0
    }

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        page_content = response.text.lower()

        phishing_keywords = ["secure", "login", "account", "verify", "update", "password", "bank", "paypal", "google", "airdrop", "crypto", "nft"]
        for keyword in phishing_keywords:
            if keyword in url.lower():
                scan_result["phishing_keywords"].append(keyword)
                scan_result["risk_score"] += 5

        if len(url) > 100:
            scan_result["length_risk"] += 10
            scan_result["risk_score"] += 10

        domain = get_domain(url)
        if "." not in domain:
            scan_result["domain_risk"] += 10
            scan_result["risk_score"] += 10

        phishing_page_keywords = ["password", "login", "bank", "credit card", "account", "social security"]
        if contains_keywords(page_content, phishing_page_keywords):
            scan_result["page_keywords_risk"] += 5
            scan_result["risk_score"] += 5

        soup = BeautifulSoup(page_content, "html.parser")
        input_forms = soup.find_all("input")
        if len(input_forms) > 0:
            scan_result["input_forms_risk"] += 10
            scan_result["risk_score"] += 10

        domain_info = whois.whois(domain)
        if "creation_date" in domain_info and "expiration_date" in domain_info:
            creation_date = min(domain_info["creation_date"]) if isinstance(domain_info["creation_date"], list) else domain_info["creation_date"]
            expiration_date = min(domain_info["expiration_date"]) if isinstance(domain_info["expiration_date"], list) else domain_info["expiration_date"]
            if (expiration_date - creation_date).days < 365:
                scan_result["domain_age_risk"] += 10
                scan_result["risk_score"] += 10

        ip_address = socket.gethostbyname(domain)
        if is_ip_suspicious(ip_address):
            scan_result["ip_suspicious_risk"] += 10
            scan_result["risk_score"] += 10

        if not is_valid_url_structure(url):
            scan_result["url_structure_risk"] += 10
            scan_result["risk_score"] += 10

        if is_js_redirect_present(page_content):
            scan_result["js_redirect_risk"] += 5
            scan_result["risk_score"] += 5

        parent_domain = ".".join(domain.split(".")[-2:])
        parent_domain_info = whois.whois(parent_domain)
        if "creation_date" in parent_domain_info:
            parent_creation_date = min(parent_domain_info["creation_date"]) if isinstance(parent_domain_info["creation_date"], list) else parent_domain_info["creation_date"]
            if (creation_date - parent_creation_date).days < 365:
                scan_result["parent_domain_age_risk"] += 10
                scan_result["risk_score"] += 10

        if not has_ssl_certificate(domain):
            scan_result["ssl_certificate_risk"] += 10
            scan_result["risk_score"] += 10

        if is_http_headers_suspicious(url):
            scan_result["http_headers_risk"] += 5
            scan_result["risk_score"] += 5

        subdomains = get_subdomains(url)
        if subdomains:
            scan_result["subdomains_risk"] += 15
            scan_result["risk_score"] += 15

        if has_unusual_characters(url):
            scan_result["unusual_characters_risk"] += 5
            scan_result["risk_score"] += 5

        if has_expired_ssl_certificate(domain):
            scan_result["expired_ssl_certificate_risk"] += 20
            scan_result["risk_score"] += 20

        if is_url_shortened(url):
            scan_result["url_shortened_risk"] += 10
            scan_result["risk_score"] += 10

        if is_high_risk_tld(url):
            scan_result["high_risk_tld_risk"] += 15
            scan_result["risk_score"] += 15

        if detect_crypto_phishing(url):
            scan_result["crypto_phishing_risk"] += 20
            scan_result["risk_score"] += 20

        if has_login_elements(page_content):
            scan_result["login_elements_risk"] += 10
            scan_result["risk_score"] += 10

        return scan_result

    except requests.exceptions.RequestException:
        scan_result["risk_score"] = 100
        return scan_result

def print_phishing_report(scan_result):
    print("Результаты анализа фишинговой ссылки:")
    print("-" * 40)
    print(f"Ссылка для проверки: {scan_result['url']}")
    print(f"Риск фишинга: {scan_result['risk_score']}%")
    if scan_result['risk_score'] >= 50:
        print("Внимание: Эта ссылка может быть фишинговой.")
    else:
        print("Ссылка выглядит надежной.")
    print("-" * 40)
    print("Детали анализа:")
    print(f"Ключевые слова фишинга в URL: {', '.join(scan_result['phishing_keywords'])}")
    print(f"Риск из-за длины URL: {scan_result['length_risk']}%")
    print(f"Риск из-за домена: {scan_result['domain_risk']}%")
    print(f"Риск из-за ключевых слов на странице: {scan_result['page_keywords_risk']}%")
    print(f"Риск из-за наличия форм ввода: {scan_result['input_forms_risk']}%")
    print(f"Риск из-за возраста домена: {scan_result['domain_age_risk']}%")
    print(f"Риск из-за подозрительного IP: {scan_result['ip_suspicious_risk']}%")
    print(f"Риск из-за структуры URL: {scan_result['url_structure_risk']}%")
    print(f"Риск из-за JavaScript-редиректа: {scan_result['js_redirect_risk']}%")
    print(f"Риск из-за возраста родительского домена: {scan_result['parent_domain_age_risk']}%")
    print(f"Риск из-за отсутствия SSL-сертификата: {scan_result['ssl_certificate_risk']}%")
    print(f"Риск из-за HTTP-заголовков: {scan_result['http_headers_risk']}%")
    print(f"Риск из-за наличия субдоменов: {scan_result['subdomains_risk']}%")
    print(f"Риск из-за необычных символов в URL: {scan_result['unusual_characters_risk']}%")
    print(f"Риск из-за истекшего SSL-сертификата: {scan_result['expired_ssl_certificate_risk']}%")
    print(f"Риск из-за использования сокращенной ссылки: {scan_result['url_shortened_risk']}%")
    print(f"Риск из-за высокорискового доменного имени: {scan_result['high_risk_tld_risk']}%")
    print(f"Риск из-за криптовалютной фишинговой активности: {scan_result['crypto_phishing_risk']}%")
    print(f"Риск из-за логирования информации о пользователе: {scan_result['login_elements_risk']}%")
    print("-" * 40)

url_to_check = input("Введите ссылку для проверки на фишинг: ")
scan_result = scan_url(url_to_check)
print_phishing_report(scan_result)