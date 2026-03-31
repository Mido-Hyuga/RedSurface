"""
HackerTarget Plugin — Free subdomain enumeration via hackertarget.com API.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class HackerTargetPlugin(PluginBase):
    name = "HackerTarget"
    description = "Passive subdomain enumeration using HackerTarget's free API."
    category = PluginCategory.DISCOVERY
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain"]
    website = "https://hackertarget.com/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={target}"
                )
                if resp.status_code != 200:
                    result.errors.append(f"HackerTarget returned {resp.status_code}")
                    result.success = False
                    return result

                text = resp.text.strip()
                if text.startswith("error"):
                    result.errors.append(text)
                    result.success = False
                    return result

                subdomains = set()
                for line in text.split("\n"):
                    parts = line.strip().split(",")
                    if parts and parts[0]:
                        host = parts[0].strip().lower()
                        if host.endswith(f".{target}") or host == target:
                            subdomains.add(host)

                result.values = sorted(subdomains)
                result.metadata = {"total": len(subdomains)}
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
