"""
RapidDNS — Free subdomain enumeration from rapiddns.io.
"""
import httpx
import re
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class RapidDNSPlugin(PluginBase):
    name = "RapidDNS"
    description = "Discover subdomains from RapidDNS.io DNS database (free, no API key)."
    category = PluginCategory.DISCOVERY
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            url = f"https://rapiddns.io/subdomain/{target}?full=1"
            async with httpx.AsyncClient(
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0"},
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    result.errors.append(f"RapidDNS returned {resp.status_code}")
                    return result

                # Parse subdomains from HTML table
                pattern = re.compile(
                    r'<td>([a-zA-Z0-9._-]+\.' + re.escape(target) + r')</td>',
                    re.IGNORECASE,
                )
                subs = set(pattern.findall(resp.text))
                result.values = sorted(subs)
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
