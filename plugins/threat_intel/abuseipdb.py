"""
AbuseIPDB — Check IP reputation and abuse reports.
"""
import socket
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class AbuseIPDBPlugin(PluginBase):
    name = "AbuseIPDB"
    description = (
        "Check if the target IP has abuse reports. Requires a free AbuseIPDB API key."
    )
    category = PluginCategory.THREAT_INTEL
    api_type = ApiType.TIERED
    requires_api_key = True
    api_key_names = ["ABUSEIPDB_KEY"]
    result_types = ["abuse_report"]
    website = "https://www.abuseipdb.com/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="abuse_report")
        try:
            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                result.errors.append(f"Could not resolve {target}")
                result.success = False
                return result

            api_key = self.api_keys.get("ABUSEIPDB_KEY")
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": api_key,
                        "Accept": "application/json",
                    },
                )
                if resp.status_code != 200:
                    result.errors.append(f"AbuseIPDB returned {resp.status_code}")
                    return result

                data = resp.json().get("data", {})

            values = []
            score = data.get("abuseConfidenceScore", 0)
            if score > 0:
                values.append(f"Abuse Score: {score}% ({data.get('totalReports', 0)} reports)")

            result.values = values
            result.metadata = {
                "ip": ip,
                "abuse_confidence_score": score,
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor", False),
                "is_public": data.get("isPublic", True),
                "last_reported": data.get("lastReportedAt"),
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
