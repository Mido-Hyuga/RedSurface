"""
Phonebook.cz — Free corporate email search engine (no API key needed).
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class PhonebookPlugin(PluginBase):
    name = "Phonebook.cz"
    description = "Search Phonebook.cz for corporate email addresses (free, no API key)."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["email"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="email")
        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(timeout=(config or {}).get("timeout", 15.0))
            emails = await collector.search_phonebook(target)
            result.values = sorted(set(emails))
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
