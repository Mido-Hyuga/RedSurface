"""
SSL Certificate Analyzer — Extract SAN domains, expiry, issuer, and cert metadata.
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class SSLAnalyzerPlugin(PluginBase):
    name = "SSL Certificate Analyzer"
    description = "Analyze SSL/TLS certificates to discover SAN domains, expiry, and issuer info."
    category = PluginCategory.DISCOVERY
    api_type = ApiType.INTERNAL
    requires_api_key = False
    result_types = ["subdomain", "ssl_info"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="subdomain")
        try:
            from modules.discovery import InfrastructureDiscoverer
            d = InfrastructureDiscoverer(use_crtsh=False, analyze_ssl=True)
            cert_info = d.get_ssl_cert_info(target)

            if cert_info is None:
                result.values = []
                result.metadata = {"error": f"Could not retrieve SSL cert for {target}"}
                return result

            cd = cert_info.to_dict()
            # SAN domains as values
            result.values = sorted(cd.get("san_domains", []))
            result.metadata = {
                "subject": cd.get("subject"),
                "issuer": cd.get("issuer"),
                "not_before": cd.get("not_before"),
                "not_after": cd.get("not_after"),
                "days_until_expiry": cd.get("days_until_expiry"),
                "is_expired": cd.get("is_expired"),
                "is_self_signed": cd.get("is_self_signed"),
                "serial_number": cd.get("serial_number"),
                "signature_algorithm": cd.get("signature_algorithm"),
            }
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
