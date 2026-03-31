"""
Archive.org Plugin — Discover historical versions of pages via the Wayback Machine.
"""
import httpx
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class ArchiveOrgPlugin(PluginBase):
    name = "Archive.org (Wayback Machine)"
    description = "Discover historical URLs and subdomains from the Wayback Machine CDX API."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain", "url"]
    website = "https://archive.org/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    "https://web.archive.org/cdx/search/cdx",
                    params={
                        "url": f"*.{target}/*",
                        "output": "json",
                        "fl": "original",
                        "collapse": "urlkey",
                        "limit": 500,
                    },
                )
                if resp.status_code != 200:
                    result.errors.append(f"Archive.org returned {resp.status_code}")
                    result.success = False
                    return result

                data = resp.json()
                subdomains = set()
                urls = []
                # First row is the header
                for row in data[1:] if len(data) > 1 else []:
                    url = row[0] if row else ""
                    urls.append(url)
                    # Extract subdomain from URL
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url if "://" in url else f"http://{url}")
                        host = parsed.hostname or ""
                        host = host.lower()
                        if host and (host.endswith(f".{target}") or host == target):
                            subdomains.add(host)
                    except Exception:
                        pass

                result.values = sorted(subdomains)
                result.metadata = {
                    "total_subdomains": len(subdomains),
                    "total_urls": len(urls),
                }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
