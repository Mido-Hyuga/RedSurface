"""
Technology Fingerprinter Plugin — Full wrapper around modules/fingerprint.py.

Exposes the complete Wappalyzer-style detection:
  - HTTP header analysis (Server, X-Powered-By, etc.)
  - Cookie-based detection (PHPSESSID, JSESSIONID, etc.)
  - HTML/JS content analysis (CMS, frameworks, analytics, CDN)
  - WAF detection (Cloudflare, Akamai, Imperva, etc.)
  - NVD CVE lookup for each detected technology

Fingerprints the main target PLUS discovered subdomains for comprehensive
technology and vulnerability mapping across the entire attack surface.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class TechFingerprinterPlugin(PluginBase):
    name = "Technology Fingerprinter"
    description = (
        "Wappalyzer-style technology detection: identifies web servers, CMS, JS frameworks, "
        "CSS frameworks, analytics, CDN, WAFs, and maps each to known CVEs via NVD. "
        "Scans the main target and up to 15 discovered subdomains."
    )
    category = PluginCategory.INTERNAL
    api_type = ApiType.INTERNAL
    requires_api_key = False
    api_key_names = ["NVD_API_KEY"]
    result_types = ["technology", "vulnerability", "waf"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="technology")
        try:
            from modules.fingerprint import TechFingerprinter

            fingerprinter = TechFingerprinter(
                timeout=(config or {}).get("timeout", 10.0),
                max_concurrent=(config or {}).get("max_concurrent", 10),
                follow_redirects=True,
                verify_ssl=False,
                nvd_api_key=self.api_keys.get("NVD_API_KEY"),
                use_nvd=(config or {}).get("use_nvd", True),
            )

            # Build list of hosts to scan: main domain + top subdomains
            hosts_to_scan = [target]

            # Try to get discovered subdomains from the scan engine context
            scan_id = (config or {}).get("scan_id")
            if scan_id:
                try:
                    from app.database import ScanResult, SessionLocal
                    db = SessionLocal()
                    subdomain_results = (
                        db.query(ScanResult)
                        .filter(
                            ScanResult.scan_id == scan_id,
                            ScanResult.result_type == "subdomain",
                        )
                        .limit(15)
                        .all()
                    )
                    for sr in subdomain_results:
                        if sr.value and sr.value != target and sr.value not in hosts_to_scan:
                            hosts_to_scan.append(sr.value)
                    db.close()
                except Exception:
                    pass  # If DB access fails, just scan the main target

            data = await fingerprinter.run(
                hostnames=hosts_to_scan,
                analyze_content=True,
            )

            techs = data.get("technologies", {})
            wafs = data.get("wafs", {})
            responses = data.get("responses", {})

            values = []
            technologies_detail = []
            vulnerabilities = []
            waf_results = {}

            for host, tech_list in techs.items():
                for tech in tech_list:
                    td = tech.to_dict()
                    label = td["name"]
                    if td.get("version"):
                        label += f" {td['version']}"

                    host_label = f"{label} ({host})" if host != target else label
                    values.append(host_label)

                    tech_entry = {
                        "host": host,
                        "name": td["name"],
                        "version": td.get("version"),
                        "source": td.get("source"),
                        "confidence": td.get("confidence"),
                        "category": td.get("category"),
                        "cve_count": len(td.get("cves", [])),
                    }
                    technologies_detail.append(tech_entry)

                    # Extract CVEs
                    for cve in td.get("cves", []):
                        vuln = {
                            "host": host,
                            "technology": label,
                            "cve_id": cve.get("cve_id"),
                            "severity": cve.get("severity"),
                            "cvss_score": cve.get("cvss_score"),
                            "description": cve.get("description"),
                            "recommendation": cve.get("recommendation"),
                        }
                        vulnerabilities.append(vuln)
                        values.append(
                            f"CVE: {cve.get('cve_id')} ({cve.get('severity', 'N/A')}) - {label}"
                        )

            for host, waf_name in wafs.items():
                if waf_name:
                    waf_results[host] = waf_name
                    values.append(f"WAF: {waf_name} ({host})")

            result.values = sorted(set(values))
            result.metadata = {
                "hosts_scanned": len(hosts_to_scan),
                "total_technologies": len(technologies_detail),
                "total_vulnerabilities": len(vulnerabilities),
                "total_wafs": len(waf_results),
                "technologies": technologies_detail,
                "vulnerabilities": vulnerabilities,
                "wafs": waf_results,
                "responses": {
                    host: {
                        "status_code": r.get("status_code"),
                        "server": r.get("server"),
                        "content_type": r.get("content_type"),
                    }
                    for host, r in responses.items()
                } if responses else {},
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result

