"""
DNS Zone Transfer — Attempt AXFR against target name servers (Active mode only).
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class ZoneTransferPlugin(PluginBase):
    name = "DNS Zone Transfer"
    description = (
        "Attempt DNS zone transfer (AXFR) to discover all DNS records. "
        "WARNING: Directly contacts the target. Active scan mode only."
    )
    category = PluginCategory.INTERNAL
    api_type = ApiType.INTERNAL
    requires_api_key = False
    result_types = ["subdomain"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        scan_mode = (config or {}).get("mode", "passive")
        if scan_mode != "active":
            result.metadata = {"skipped": True, "reason": "Only runs in Active scan mode"}
            return result
        try:
            from modules.active_recon import ActiveRecon
            recon = ActiveRecon(timeout=(config or {}).get("timeout", 10.0))
            subs = await recon.zone_transfer(target)
            result.values = sorted(subs)
            result.metadata = {"success": bool(subs), "count": len(subs)}
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
