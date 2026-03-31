"""
GitHub Email Discovery — Find developer emails from GitHub public profiles.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class GitHubEmailsPlugin(PluginBase):
    name = "GitHub Email Discovery"
    description = "Find developer email addresses from GitHub public profiles and commits."
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    api_key_names = ["GITHUB_TOKEN"]
    result_types = ["email", "person"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="email")
        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(
                timeout=(config or {}).get("timeout", 15.0),
                github_token=self.api_keys.get("GITHUB_TOKEN"),
            )
            people = await collector.search_github(target)
            result.values = sorted(set(p.email for p in people if p.email))
            result.metadata = {
                "people": [p.to_dict() for p in people],
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
