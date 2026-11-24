"""Device identity: basicdeviceinfo.cgi with a param-tree fallback, and API discovery."""

from __future__ import annotations

import logging

from .client import CameraClient, CameraError
from .params import ParamTree

log = logging.getLogger(__name__)

_FIELDS = ["ProdFullName", "ProdNbr", "ProdType", "SerialNumber", "Version", "HardwareID",
           "BuildDate", "Architecture", "Soc", "SocSerialNumber"]


def basic_device_info(client: CameraClient) -> dict[str, str]:
    for method in ("getAllProperties", "getAllUnrestrictedProperties"):
        try:
            resp = client.post_json("/axis-cgi/basicdeviceinfo.cgi", {"apiVersion": "1.0", "method": method})
            data = resp.json()
        except CameraError as e:
            if e.code == "AUTH_FAILED":
                raise
            log.debug("%s: basicdeviceinfo %s failed: %s", client.camera.host, method, e)
            continue
        except ValueError:
            continue
        props = (data.get("data") or {}).get("propertyList")
        if props:
            return {k: str(v) for k, v in props.items()}
    return {}


def device_info_from_params(params: ParamTree) -> dict[str, str]:
    """Fallback / supplement from the parameter tree."""
    m = {
        "ProdFullName": "root.Brand.ProdFullName",
        "ProdNbr": "root.Brand.ProdNbr",
        "ProdType": "root.Brand.ProdType",
        "Version": "root.Properties.Firmware.Version",
        "SerialNumber": "root.Properties.System.SerialNumber",
        "HardwareID": "root.Properties.System.HardwareID",
        "Architecture": "root.Properties.System.Architecture",
    }
    return {k: params.get(p) for k, p in m.items() if params.get(p)}


def mac_from_params(params: ParamTree) -> str:
    for name in ("root.Network.eth0.MACAddress", "root.Network.Interface.I0.Link.MACAddress"):
        if params.get(name):
            return params.get(name)
    serial = params.get("root.Properties.System.SerialNumber") or ""
    if len(serial) == 12:  # AXIS serial number is the MAC address
        return ":".join(serial[i:i + 2] for i in range(0, 12, 2)).upper()
    return ""


def api_list(client: CameraClient) -> list[dict]:
    try:
        resp = client.post_json("/axis-cgi/apidiscovery.cgi", {"apiVersion": "1.0", "method": "getApiList"})
        return list((resp.json().get("data") or {}).get("apiList") or [])
    except (CameraError, ValueError) as e:
        if isinstance(e, CameraError) and e.code == "AUTH_FAILED":
            raise
        log.debug("%s: apidiscovery failed: %s", client.camera.host, e)
        return []
