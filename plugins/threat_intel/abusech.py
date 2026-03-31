"""
abuse.ch Plugin — Check domains/IPs against abuse.ch threat databases.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class AbuseCHPlugin(PluginBase):
    name = "abuse.ch"
    description = "Check if a domain or host is malicious according to abuse.ch threat databases."
    category = PluginCategory.THREAT_INTEL
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["threat_indicator"]
    website = "https://www.abuse.ch/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="threat_indicator")
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Check URLhaus for malicious URLs
                resp = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": target},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("query_status") == "no_results":
                        result.values = []
                        result.metadata = {"status": "clean", "source": "urlhaus"}
                    else:
                        urls_count = data.get("urls_online", 0)
                        urls = data.get("urls", [])
                        threats = []
                        for url_entry in urls[:20]:
                            threats.append(
                                f"{url_entry.get('url', 'N/A')} [{url_entry.get('threat', 'unknown')}]"
                            )
                        result.values = threats
                        result.metadata = {
                            "status": "malicious",
                            "urls_online": urls_count,
                            "source": "urlhaus",
                            "first_seen": data.get("firstseen"),
                            "tags": data.get("tags"),
                        }
                else:
                    result.errors.append(f"abuse.ch returned {resp.status_code}")
                    result.success = False
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
