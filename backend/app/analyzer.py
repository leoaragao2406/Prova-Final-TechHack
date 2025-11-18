import json
import math
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
import Levenshtein
import whois
from bs4 import BeautifulSoup

from .config import (
    BLACKLIST_URLS,
    DYNAMIC_DNS_PROVIDERS,
    KNOWN_BRANDS,
    SUSPICIOUS_KEYWORDS,
)
from .models import AnalysisResult, HeuristicResult

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
)


async def fetch_blacklists() -> set[str]:
    entries: set[str] = set()
    async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": USER_AGENT}) as client:
        for url in BLACKLIST_URLS:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    domain = line.strip().lower()
                    if domain:
                        entries.add(domain)
            except Exception:
                continue
    return entries


def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return hostname.lower()


def check_domain_patterns(domain: str) -> tuple[bool, str]:
    subdomain_count = domain.count(".")
    has_numbers = bool(re.search(r"[a-zA-Z]\d", domain))
    has_special = bool(re.search(r"[-_@]", domain))
    suspicious = subdomain_count > 3 or has_numbers or has_special
    details = []
    if subdomain_count > 3:
        details.append("excesso de subdomínios")
    if has_numbers:
        details.append("números substituindo letras")
    if has_special:
        details.append("caracteres especiais incomuns")
    return suspicious, ", ".join(details) if details else "domínio sem indícios óbvios"


def check_dynamic_dns(domain: str) -> bool:
    return any(provider in domain for provider in DYNAMIC_DNS_PROVIDERS)


def fetch_whois_age(domain: str) -> tuple[int | None, str]:
    try:
        record = whois.whois(domain)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return None, "sem informação de criação"
        if not isinstance(creation_date, datetime):
            creation_date = datetime.strptime(str(creation_date), "%Y-%m-%d")
        delta = datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)
        days = delta.days
        return days, f"domínio criado há {days} dias"
    except Exception as exc:
        return None, f"erro ao consultar WHOIS: {exc}"


async def fetch_page(url: str) -> tuple[str, str, list[str]]:
    final_url = url
    redirects: list[str] = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, headers={"User-Agent": USER_AGENT}) as client:
        resp = await client.get(url)
        final_url = str(resp.url)
        redirects = [str(h.headers.get("location", "")) for h in resp.history if h.headers.get("location")]
        return resp.text, final_url, redirects


def analyze_content(html: str) -> tuple[bool, list[str]]:
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    login_detected = any(
        "password" in (input_.get("type") or "").lower() for form in forms for input_ in form.find_all("input")
    )
    text = soup.get_text(" ").lower()
    matches = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in text]
    return login_detected, matches


def check_ssl_certificate(domain: str) -> tuple[bool, str, int | None]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer.get("commonName") or issuer.get("organizationName", "desconhecido")
                expires = cert.get("notAfter")
                if expires:
                    expires_dt = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expires_dt - datetime.utcnow()).days
                else:
                    days_left = None
                
                # Verificar subjectAltName corretamente (é uma lista de tuplas)
                san_list = cert.get("subjectAltName", [])
                cert_domains = []
                for san_type, san_value in san_list:
                    if san_type == "DNS":
                        cert_domains.append(san_value.lower())
                
                # Verificar também no subject
                subject = cert.get("subject", [])
                subject_dict = dict(x[0] for x in subject)
                if "commonName" in subject_dict:
                    cert_domains.append(subject_dict["commonName"].lower())
                
                # Verificar se o domínio ou domínio base está no certificado
                domain_lower = domain.lower()
                base_domain = ".".join(domain_lower.split(".")[-2:]) if "." in domain_lower else domain_lower
                match = any(
                    domain_lower == cert_dom or 
                    cert_dom == f"*.{base_domain}" or
                    domain_lower.endswith(f".{cert_dom.replace('*.', '')}")
                    for cert_dom in cert_domains
                )
                
                valid = match and (days_left is None or days_left > 0)
                return valid, issuer_name, days_left
    except Exception as exc:
        return False, f"erro SSL: {exc}", None


def check_brand_similarity(domain: str) -> tuple[bool, str]:
    # Se o domínio É uma marca conhecida, não é similaridade suspeita
    if domain in KNOWN_BRANDS or any(domain.endswith(f".{brand}") for brand in KNOWN_BRANDS):
        return False, "domínio de marca conhecida"
    
    min_distance = math.inf
    closest = ""
    for brand in KNOWN_BRANDS:
        # Comparar apenas o domínio base (sem subdomínios)
        domain_base = ".".join(domain.split(".")[-2:]) if "." in domain else domain
        brand_base = ".".join(brand.split(".")[-2:]) if "." in brand else brand
        distance = Levenshtein.distance(domain_base, brand_base)
        if distance < min_distance:
            min_distance = distance
            closest = brand
    similar = min_distance <= 3 and min_distance > 0
    return similar, f"similar ao domínio {closest} (distância {min_distance})"


async def analyze_url(url: str, blacklist_cache: set[str] | None = None) -> AnalysisResult:
    url = str(url)
    timestamp = datetime.now(timezone.utc)
    domain = extract_domain(url)

    heuristics: list[HeuristicResult] = []
    metadata: dict = {}
    score = 0

    blacklists = blacklist_cache or await fetch_blacklists()
    in_blacklist = any(domain.endswith(entry) for entry in blacklists)
    heuristics.append(
        HeuristicResult(
            name="Listas de phishing",
            passed=not in_blacklist,
            details="domínio encontrado em listas suspeitas" if in_blacklist else "não encontrado nas listas",
            score_impact=-40 if in_blacklist else 5,
        )
    )
    score += heuristics[-1].score_impact

    suspicious, details = check_domain_patterns(domain)
    heuristics.append(
        HeuristicResult(
            name="Padrões do domínio",
            passed=not suspicious,
            details=details,
            score_impact=-10 if suspicious else 3,
        )
    )
    score += heuristics[-1].score_impact

    dynamic_dns = check_dynamic_dns(domain)
    heuristics.append(
        HeuristicResult(
            name="DNS dinâmico",
            passed=not dynamic_dns,
            details="provedor dinâmico identificado" if dynamic_dns else "DNS tradicional",
            score_impact=-15 if dynamic_dns else 2,
        )
    )
    score += heuristics[-1].score_impact

    age_days, age_details = fetch_whois_age(domain)
    young = age_days is not None and age_days < 180
    heuristics.append(
        HeuristicResult(
            name="Idade do domínio",
            passed=not young,
            details=age_details,
            score_impact=-20 if young else 4,
        )
    )
    if age_days is not None:
        metadata["domain_age_days"] = age_days
    score += heuristics[-1].score_impact

    try:
        html, final_url, redirects = await fetch_page(url)
        metadata["final_url"] = final_url
        metadata["redirect_chain"] = redirects
        redirect_flag = len(redirects) > 2
        heuristics.append(
            HeuristicResult(
                name="Redirecionamentos",
                passed=not redirect_flag,
                details=f"{len(redirects)} redirecionamentos detectados",
                score_impact=-10 if redirect_flag else 2,
            )
        )
        score += heuristics[-1].score_impact

        login_detected, keyword_hits = analyze_content(html)
        heuristics.append(
            HeuristicResult(
                name="Formulários sensíveis",
                passed=not login_detected,
                details="formulário de login encontrado" if login_detected else "nenhum formulário de login",
                score_impact=-15 if login_detected else 2,
            )
        )
        score += heuristics[-1].score_impact

        heuristics.append(
            HeuristicResult(
                name="Palavras sensíveis",
                passed=not keyword_hits,
                details=f"palavras suspeitas: {', '.join(keyword_hits)}" if keyword_hits else "sem termos críticos",
                score_impact=-8 if keyword_hits else 1,
            )
        )
        score += heuristics[-1].score_impact
    except Exception as exc:
        metadata["content_error"] = str(exc)

    ssl_valid, ssl_details, ssl_days = check_ssl_certificate(domain)
    heuristics.append(
        HeuristicResult(
            name="Certificado SSL",
            passed=ssl_valid,
            details=f"{ssl_details}, {ssl_days} dias restantes" if ssl_days is not None else ssl_details,
            score_impact=10 if ssl_valid else -15,
        )
    )
    if ssl_days is not None:
        metadata["ssl_days_left"] = ssl_days
    metadata["ssl_details"] = ssl_details
    score += heuristics[-1].score_impact

    similar_brand, similarity_details = check_brand_similarity(domain)
    heuristics.append(
        HeuristicResult(
            name="Similaridade com marcas",
            passed=not similar_brand,
            details=similarity_details,
            score_impact=-12 if similar_brand else 3,
        )
    )
    score += heuristics[-1].score_impact

    risk_level = "ALTO" if score <= -10 else "MÉDIO" if score < 20 else "BAIXO"

    return AnalysisResult(
        url=url,
        domain=domain,
        timestamp=timestamp,
        overall_score=score,
        risk_level=risk_level,
        heuristics=heuristics,
        metadata=metadata,
    )

