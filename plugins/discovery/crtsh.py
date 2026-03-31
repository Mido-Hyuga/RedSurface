"""
Certificate Transparency (crt.sh) — Subdomain discovery via CT logs.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class CrtshPlugin(PluginBase):
    name = "Certificate Transparency (crt.sh)"
    description = "Discover subdomains from SSL/TLS certificate transparency logs."
    category = PluginCategory.DISCOVERY
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["subdomain"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            from modules.discovery import InfrastructureDiscoverer
            d = InfrastructureDiscoverer(use_crtsh=True, analyze_ssl=False)
            subs = await d.discover_subdomains_crtsh(target)
            result.values = sorted(subs)
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
