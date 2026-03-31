"""
SecurityTrails — Subdomain discovery via SecurityTrails API.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class SecurityTrailsPlugin(PluginBase):
    name = "SecurityTrails"
    description = "Discover subdomains using the SecurityTrails API."
    category = PluginCategory.DISCOVERY
    api_type = ApiType.TIERED
    requires_api_key = True
    api_key_names = ["SECURITYTRAILS_KEY"]
    result_types = ["subdomain"]
    website = "https://securitytrails.com/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            from modules.discovery import InfrastructureDiscoverer
            d = InfrastructureDiscoverer(use_crtsh=False, analyze_ssl=False)
            d.set_api_keys(securitytrails_key=self.api_keys.get("SECURITYTRAILS_KEY"))
            subs = await d.discover_subdomains_securitytrails(target)
            result.values = sorted(subs)
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
