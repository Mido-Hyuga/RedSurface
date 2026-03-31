"""
Directory Enumeration — Discover hidden files and directories on web servers (Active mode only).
"""
from plugins.base import PluginBase, PluginResult, PluginCategory, ApiType


class DirEnumPlugin(PluginBase):
    name = "Directory Enumeration"
    description = (
        "Brute-force directories and files on web servers (admin panels, APIs, configs). "
        "WARNING: Directly contacts the target. Active scan mode only."
    )
    category = PluginCategory.INTERNAL
    api_type = ApiType.INTERNAL
    requires_api_key = False
    result_types = ["directory"]

    async def run(self, target: str, config: dict = None) -> PluginResult:
        result = PluginResult(plugin_name=self.name, result_type="directory")
        scan_mode = (config or {}).get("mode", "passive")
        if scan_mode != "active":
            result.metadata = {"skipped": True, "reason": "Only runs in Active scan mode"}
            return result
        try:
            from modules.active_recon import ActiveRecon
            recon = ActiveRecon(
                timeout=(config or {}).get("timeout", 10.0),
                max_concurrent=(config or {}).get("max_concurrent", 20),
            )
            values = []
            dirs_metadata = {}
            for scheme in ["https", "http"]:
                url = f"{scheme}://{target}"
                try:
                    dirs = await recon.directory_enum(url)
                    for d in dirs:
                        path = d.get("path", "")
                        status = d.get("status_code", "")
                        size = d.get("content_length", "")
                        values.append(f"{path} ({status}, {size}B)")
                    dirs_metadata[url] = dirs
                    if dirs:
                        break  # Success on HTTPS, skip HTTP
                except Exception as e:
                    dirs_metadata[url] = {"error": str(e)}

            result.values = values
            result.metadata = {"directories": dirs_metadata}
        except Exception as e:
            result.errors.append(str(e))
            result.success = False
        return result
