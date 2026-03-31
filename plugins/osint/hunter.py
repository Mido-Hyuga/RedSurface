"""
Hunter.io — Verified business email finder (requires API key).
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class HunterPlugin(PluginBase):
    name = "Hunter.io"
    description = "Find verified business email addresses and employee names using Hunter.io API."
    category = PluginCategory.OSINT
    api_type = ApiType.TIERED
    requires_api_key = True
    api_key_names = ["HUNTER_KEY"]
    result_types = ["email", "person"]
    website = "https://hunter.io/"

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="email")
        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(timeout=(config or {}).get("timeout", 15.0))
            people = await collector.search_hunter(
                domain=target,
                api_key=self.api_keys.get("HUNTER_KEY"),
            )
            result.values = sorted(set(p.email for p in people if p.email))
            result.metadata = {
                "people": [p.to_dict() for p in people],
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
