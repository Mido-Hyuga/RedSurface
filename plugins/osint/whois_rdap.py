"""
WHOIS/RDAP Plugin — Dedicated wrapper for WHOIS/RDAP contact extraction from osint.py.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class WHOISPlugin(PluginBase):
    name = "WHOIS / RDAP Lookup"
    description = (
        "Extract domain registration data, admin/tech contacts, registrar info, "
        "and name servers via RDAP protocol."
    )
    category = PluginCategory.OSINT
    api_type = ApiType.FREE
    requires_api_key = False
    result_types = ["contact", "registrar"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="contact")
        try:
            from modules.osint import OSINTCollector

            collector = OSINTCollector(
                timeout=(config or {}).get("timeout", 15.0),
            )

            contacts = await collector.search_whois_contacts(target)
            values = []
            people = []
            for person in contacts:
                pd = person.to_dict()
                people.append(pd)
                if person.email:
                    values.append(person.email)

            # DNS email infrastructure hints
            dns_hints = await collector.extract_dns_email_hints(target)

            result.values = sorted(set(values))
            result.metadata = {
                "contacts": people,
                "dns_hints": dns_hints,
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
