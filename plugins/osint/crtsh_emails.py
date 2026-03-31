"""
crt.sh Email Search — Find email addresses from SSL certificate CT logs.
Different from subdomain discovery — looks for emails in cert subject/SAN fields.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class CrtshEmailPlugin(PluginBase):
    name = "crt.sh Email Search"
    description = "Find email addresses from SSL certificate transparency logs."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["email"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="email")
        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(timeout=(config or {}).get("timeout", 15.0))
            emails = await collector.search_crtsh(target)
            result.values = sorted(set(emails))
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
