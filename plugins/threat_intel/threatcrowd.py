"""
ThreatCrowd — Free threat intelligence: domains, IPs, emails, and malware hashes.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class ThreatCrowdPlugin(PluginBase):
    name = "ThreatCrowd"
    description = (
        "Query ThreatCrowd for threat intel: related subdomains, IPs, "
        "email addresses, and associated malware."
    )
    category = PluginCategory.THREAT_INTEL
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain", "email", "ip"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, params={"domain": target})
                if resp.status_code != 200:
                    result.errors.append(f"ThreatCrowd returned {resp.status_code}")
                    return result

                data = resp.json()

            if data.get("response_code") == "0":
                result.values = []
                return result

            values = []
            # Subdomains
            for sub in data.get("subdomains", []):
                values.append(sub)

            # Emails
            for email in data.get("emails", []):
                values.append(email)

            result.values = sorted(set(values))
            result.metadata = {
                "ips": data.get("resolutions", [])[:20],
                "emails": data.get("emails", []),
                "subdomains": data.get("subdomains", []),
                "references": data.get("references", []),
                "votes": data.get("votes"),
                "permalink": data.get("permalink"),
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
