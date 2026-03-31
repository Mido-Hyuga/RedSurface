"""
BufferOver — Free DNS records and subdomains via dns.bufferover.run.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class BufferOverPlugin(PluginBase):
    name = "BufferOver DNS"
    description = "Discover subdomains from BufferOver's DNS database (free, no API key)."
    category = PluginCategory.DISCOVERY
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            url = f"https://dns.bufferover.run/dns?q=.{target}"
            async with httpx.AsyncClient(
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    result.errors.append(f"BufferOver returned {resp.status_code}")
                    return result

                data = resp.json()

            subs = set()
            for record in data.get("FDNS_A", []) or []:
                # Records are in format "ip,hostname"
                if "," in record:
                    hostname = record.split(",", 1)[1].strip().lower()
                    if hostname.endswith(f".{target}") or hostname == target:
                        subs.add(hostname)

            for record in data.get("RDNS", []) or []:
                if "," in record:
                    hostname = record.split(",", 1)[1].strip().lower()
                    if hostname.endswith(f".{target}") or hostname == target:
                        subs.add(hostname)

            result.values = sorted(subs)
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
