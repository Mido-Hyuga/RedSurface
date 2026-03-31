"""
IP Resolver & Cloud Detector — Resolves discovered subdomains to IPs and
detects cloud providers from CNAME records.

Uses the full InfrastructureDiscoverer.resolve_dns() and detect_cloud_provider()
from the original discovery module.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class IPResolverPlugin(PluginBase):
    name = "IP Resolver & Cloud Detector"
    description = (
        "Resolves discovered subdomains to IP addresses (IPv4/IPv6), "
        "extracts CNAME records, and identifies cloud providers "
        "(AWS, Azure, GCP, Cloudflare, Fastly, Akamai, Heroku, Vercel, Netlify, etc.)."
    )
    category = PluginCategory.INTERNAL
    api_type = ApiType.INTERNAL
    requires_api_key = False
    result_types = ["ip", "cloud_service"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="ip")
        try:
            from modules.discovery import InfrastructureDiscoverer

            discoverer = InfrastructureDiscoverer(
                timeout=(config or {}).get("timeout", 5.0),
                max_concurrent=(config or {}).get("max_concurrent", 30),
                analyze_ssl=False,
            )

            # Resolve the target itself
            asset = await discoverer.resolve_dns(target)

            values = []
            cloud_services = []
            all_ips = {}
            all_cnames = {}
            all_clouds = {}

            if asset.ips:
                for ip in asset.ips:
                    values.append(f"{target} → {ip}")
                all_ips[target] = asset.ips

            if asset.cnames:
                all_cnames[target] = asset.cnames

            if asset.cloud_providers:
                for cp in asset.cloud_providers:
                    cloud_services.append(f"{target}: {cp}")
                    values.append(f"Cloud: {cp} ({target})")
                all_clouds[target] = asset.cloud_providers

            result.values = values
            result.metadata = {
                "resolved_hosts": len(all_ips),
                "total_ips": sum(len(v) for v in all_ips.values()),
                "total_cloud_services": len(cloud_services),
                "ips": all_ips,
                "cnames": all_cnames,
                "cloud_providers": all_clouds,
                "cloud_services_list": cloud_services,
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
