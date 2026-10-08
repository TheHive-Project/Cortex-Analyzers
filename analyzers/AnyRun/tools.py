import traceback
from functools import wraps

from anyrun import RunTimeException
from anyrun.connectors import LookupConnector, SandboxConnector
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun.connectors.sandbox.operation_systems import (
    AndroidConnector,
    LinuxConnector,
    WindowsConnector,
)
from cortexutils.analyzer import Analyzer


def catch_exceptions(func):
    @wraps(func)
    def wrapper(self: Analyzer, *args, **kwargs):
        try:
            result = func(self, *args, **kwargs)
            return result
        except RunTimeException as exc:
            self.error(str(exc))
        except Exception:
            self.unexpectedError(traceback.format_exc())

    return wrapper


def extract_sandbox_iocs(report: dict, field: str, ioc: str) -> str | None:
    if content := report.get("data").get("network").get(field):
        return ",".join(
            [
                obj.get(ioc)
                for obj in content
                if obj.get("reputation") in ("suspicious", "malicious")
            ]
        )
    return ""


def get_windows_sandbox_connector(
    api_key: str, version: str, verify_ssl: bool, root_url: str, proxy: str = None
) -> WindowsConnector:
    """Builds ANY.RUN Sandbox instance for the Windows OS"""
    return SandboxConnector().windows(
        api_key,
        integration=version,
        verify_ssl=verify_ssl,
        proxy=proxy,
        root_url=root_url,
    )


def get_linux_sandbox_connector(
    api_key: str, version: str, verify_ssl: bool, root_url: str, proxy: str = None
) -> LinuxConnector:
    """Builds ANY.RUN Sandbox instance for the Linux OS"""
    return SandboxConnector().linux(
        api_key,
        integration=version,
        verify_ssl=verify_ssl,
        proxy=proxy,
    )


def get_android_sandbox_connector(
    api_key: str, version: str, verify_ssl: bool, root_url: str, proxy: str = None
) -> AndroidConnector:
    """Builds ANY.RUN Sandbox instance for the Android OS"""
    return SandboxConnector().android(
        api_key,
        integration=version,
        verify_ssl=verify_ssl,
        proxy=proxy,
    )


def get_base_sandbox_connector(
    api_key: str, version: str, verify_ssl: bool, root_url: str, proxy: str = None
) -> BaseSandboxConnector:
    """Builds ANY.RUN Sandbox generic instance"""
    return BaseSandboxConnector(
        api_key,
        integration=version,
        verify_ssl=verify_ssl,
        proxy=proxy,
        root_url=root_url,
    )


def get_ti_lookup_connector(
    api_key: str, version: str, verify_ssl: bool, proxy: str = None
) -> LookupConnector:
    """Builds ANY.RUN Sandbox generic instance"""
    return LookupConnector(
        api_key,
        integration=version,
        verify_ssl=verify_ssl,
        proxy=proxy,
    )


connectors = {
    "windows": get_windows_sandbox_connector,
    "linux": get_linux_sandbox_connector,
    "android": get_android_sandbox_connector,
    "base": get_base_sandbox_connector,
    "ti_lookup": get_ti_lookup_connector,
}
