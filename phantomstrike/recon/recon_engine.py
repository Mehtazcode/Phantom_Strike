import requests
"""
recon/recon_engine.py -- PHASE 1 (Weeks 3-7)
"""

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver

from phantomstrike.core.config import OUTPUT_DIR, WORDLIST_DIR, SHODAN_API_KEY
from phantomstrike.utils import logger


class ReconEngine:
    def __init__(self, target_domain: str):
        self.target = target_domain
        self.results = {
            "target": target_domain,
            "subdomains": [],
            "whois": {},
            "shodan": [],
            "dorks": [],
        }

    def _query_crtsh(self) -> list:
        """
        Query crt.sh (Certificate Transparency log search) for subdomains.

        WHY: This is 100% passive -- we never touch the target, only a
        public third-party CT log aggregator. Certs get logged publicly
        the moment they're issued, so this often finds internal/staging
        subdomains that never show up in a wordlist brute force.
        """
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        data = None
        for attempt in range(2):
            try:
                resp = requests.get(url, timeout=25)
                resp.raise_for_status()
                data = resp.json()
                break
            except (requests.RequestException, ValueError) as e:
                logger.warning(f"crt.sh attempt {attempt + 1}/2 failed: {e}")
        if data is None:
            logger.warning("crt.sh unavailable after retry -- continuing with wordlist results only")
            return []

        names = set()
        for entry in data:
            for name in entry.get("name_value", "").split(chr(10)):
                name = name.strip().lower()
                if name.startswith("*."):
                    name = name[2:]
                if name.endswith(self.target.lower()) and name != self.target.lower():
                    names.add(name)

        logger.success(f"crt.sh returned {len(names)} unique subdomain candidates")
        return sorted(names)

    def enumerate_subdomains(self, wordlist_path: str = None) -> list:
        """
        Brute-forces subdomains using a wordlist and DNS resolution.
        Also merges passive results from crt.sh Certificate Transparency logs.
        Uses ThreadPoolExecutor so queries run concurrently.
        """
        if wordlist_path is None:
            wordlist_path = os.path.join(WORDLIST_DIR, "subdomains.txt")

        try:
            with open(wordlist_path, "r") as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Wordlist not found at {wordlist_path}")
            return []

        wordlist_candidates = [f"{w}.{self.target}" for w in words]
        crtsh_candidates = self._query_crtsh()
        all_candidates = sorted(set(wordlist_candidates) | set(crtsh_candidates))

        logger.info(
            f"Testing {len(all_candidates)} subdomains against {self.target} "
            f"({len(wordlist_candidates)} wordlist + {len(crtsh_candidates)} crt.sh, deduped)"
        )
        found = []

        def check_subdomain(candidate: str):
            try:
                answers = dns.resolver.resolve(candidate, "A")
                ips = [rdata.address for rdata in answers]
                return {"subdomain": candidate, "ips": ips}
            except (dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.exception.Timeout,
                    Exception):
                return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, c): c for c in all_candidates}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    logger.success(
                        f"Found: {result['subdomain']} -> {', '.join(result['ips'])}"
                    )

        logger.info(f"Subdomain enumeration complete -- {len(found)} found")
        return found
    def whois_lookup(self) -> dict:
        """
        Queries WHOIS data for the target domain.
        Returns registrar, dates, nameservers, and org info.

        Why this matters in recon: WHOIS reveals who owns the domain,
        when it expires (useful for domain takeover research), which
        registrar they use, and often the org name which helps map
        out related infrastructure.
        """
        import whois as whois_lib
        logger.info(f"Running WHOIS lookup on {self.target}")

        try:
            w = whois_lib.whois(self.target)

            # whois returns dates as lists or single values depending
            # on the TLD -- normalize everything to strings for clean JSON
            def normalize(val):
                if val is None:
                    return None
                if isinstance(val, list):
                    return [str(v) for v in val]
                return str(val)

            result = {
                "domain_name":     normalize(w.domain_name),
                "registrar":       normalize(w.registrar),
                "creation_date":   normalize(w.creation_date),
                "expiration_date": normalize(w.expiration_date),
                "updated_date":    normalize(w.updated_date),
                "name_servers":    normalize(w.name_servers),
                "org":             normalize(w.org),
                "country":         normalize(w.country),
                "emails":          normalize(w.emails),
            }

            logger.success(f"WHOIS complete -- registrar: {w.registrar}")
            self.results["whois"] = result
            return result

        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return {}

    def shodan_search(self) -> list:
        """TODO -- Phase 1, Week 6"""
        if not SHODAN_API_KEY:
            logger.warning("No Shodan API key set -- skipping shodan_search()")
            return []
        logger.warning("shodan_search() not implemented yet -- Phase 1")
        raise NotImplementedError("Build this in Phase 1, Week 6")

    def generate_dorks(self) -> list:
        """
        Generate Google dork queries for passive OSINT against self.target.

        WHY: Dorks are NOT auto-executed against Google -- scraping search
        results programmatically breaks Google's ToS and risks IP blocks,
        and defeats the point of "passive" recon. Instead we generate
        ready-to-use query strings for manual use or a licensed search API.
        """
        logger.info(f"Generating Google dorks for {self.target}")

        dork_categories = {
            "exposed_files": [
                f'site:{self.target} filetype:pdf',
                f'site:{self.target} filetype:xls OR filetype:xlsx',
                f'site:{self.target} filetype:doc OR filetype:docx',
                f'site:{self.target} filetype:sql',
                f'site:{self.target} filetype:log',
            ],
            "login_admin_panels": [
                f'site:{self.target} inurl:login',
                f'site:{self.target} inurl:admin',
                f'site:{self.target} intitle:"admin login"',
                f'site:{self.target} inurl:wp-admin',
            ],
            "directory_listing": [
                f'site:{self.target} intitle:"index of /"',
                f'site:{self.target} intitle:"index of" "parent directory"',
            ],
            "config_backup_leaks": [
                f'site:{self.target} filetype:env',
                f'site:{self.target} filetype:bak OR filetype:old OR filetype:backup',
                f'site:{self.target} inurl:config filetype:json',
                f'site:{self.target} filetype:xml inurl:config',
            ],
            "error_pages": [
                f'site:{self.target} "sql syntax near"',
                f'site:{self.target} "warning: mysql"',
                f'site:{self.target} intitle:"error" "stack trace"',
            ],
            "subdomain_discovery": [
                f'site:*.{self.target} -site:www.{self.target}',
            ],
        }

        dorks = []
        for category, queries in dork_categories.items():
            for q in queries:
                dorks.append({"category": category, "query": q})

        self.results["dorks"] = dorks
        logger.success(f"Generated {len(dorks)} dorks across {len(dork_categories)} categories")
        return dorks

    def run_all(self, run_dorks: bool = False) -> dict:
        """Orchestrates all recon steps and saves combined result to output/."""
        logger.info(f"Starting recon against {self.target}")

        try:
            self.results["subdomains"] = self.enumerate_subdomains()
        except NotImplementedError:
            pass

        try:
            self.results["whois"] = self.whois_lookup()
        except NotImplementedError:
            pass

        try:
            self.results["shodan"] = self.shodan_search()
        except NotImplementedError:
            pass

        if run_dorks:
            try:
                self.results["dorks"] = self.generate_dorks()
            except NotImplementedError:
                pass
        else:
            logger.info("Skipping dork generation (pass --dorks to enable)")

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        out_path = os.path.join(OUTPUT_DIR, f"recon_{self.target}.json")
        with open(out_path, "w") as f:
            json.dump(self.results, f, indent=2)

        logger.success(f"Recon results saved to {out_path}")
        return self.results
