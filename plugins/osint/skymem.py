"""
Skymem — Email aggregator that scrapes public sources.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class SkymemPlugin(PluginBase):
    name = "Skymem"
    description = "Scrape Skymem.info for aggregated corporate email addresses."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["email"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="email")
        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(timeout=(config or {}).get("timeout", 15.0))
            emails = await collector.search_skymem(target)
            result.values = sorted(set(emails))
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
