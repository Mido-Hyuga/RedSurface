"""
CommonCrawl Plugin — Find URLs from the CommonCrawl index.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class CommonCrawlPlugin(PluginBase):
    name = "CommonCrawl"
    description = "Discover subdomains and URLs from CommonCrawl's web archive index."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain"]
    website = "https://commoncrawl.org/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get the latest index collection
                index_resp = await client.get(
                    "https://index.commoncrawl.org/collinfo.json"
                )
                if index_resp.status_code != 200:
                    result.errors.append("Could not fetch CommonCrawl index list")
                    result.success = False
                    return result

                indexes = index_resp.json()
                if not indexes:
                    result.errors.append("No CommonCrawl indexes available")
                    result.success = False
                    return result

                # Use the latest index
                latest_api = indexes[0].get("cdx-api", "")
                if not latest_api:
                    result.errors.append("No CDX API URL in latest index")
                    result.success = False
                    return result

                resp = await client.get(
                    latest_api,
                    params={
                        "url": f"*.{target}",
                        "output": "json",
                        "fl": "url",
                        "limit": 500,
                    },
                )
                if resp.status_code != 200:
                    result.errors.append(f"CommonCrawl CDX returned {resp.status_code}")
                    result.success = False
                    return result

                subdomains = set()
                for line in resp.text.strip().split("\n"):
                    try:
                        import json
                        entry = json.loads(line)
                        url = entry.get("url", "")
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        host = (parsed.hostname or "").lower()
                        if host and (host.endswith(f".{target}") or host == target):
                            subdomains.add(host)
                    except Exception:
                        continue

                result.values = sorted(subdomains)
                result.metadata = {"total": len(subdomains)}
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
