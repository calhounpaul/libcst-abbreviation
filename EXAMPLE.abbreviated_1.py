from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
import functools as ft
import importlib
import logging
import os
import pathlib
import sys
import time
from types import ModuleType
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypedDict, cast

from awesomeversion import (
    AwesomeVersion,
    AwesomeVersionException,
    AwesomeVersionStrategy,
)
from propcache.api import cached_property
import voluptuous as vol

from . import generated
from .const import Platform
from .core import HomeAssistant, callback
from .generated.application_credentials import APPLICATION_CREDENTIALS
from .generated.bluetooth import BLUETOOTH
from .generated.config_flows import FLOWS
from .generated.dhcp import DHCP
from .generated.mqtt import MQTT
from .generated.ssdp import SSDP
from .generated.usb import USB
from .generated.zeroconf import HOMEKIT, ZEROCONF
from .helpers.json import json_bytes, json_fragment
from .util.hass_dict import HassKey
from .util.json import JSON_DECODE_EXCEPTIONS, json_loads

MOVED_ZEROCONF_PROPS = ("macaddress", "model", "manufacturer")


class DHCPMatcherRequired(TypedDict, total=True):
    """Matcher for the dhcp integration for required fields."""

    domain: str


class DHCPMatcherOptional(TypedDict, total=False):
    """Matcher for the dhcp integration for optional fields."""

    macaddress: str
    hostname: str
    registered_devices: bool


class DHCPMatcher(DHCPMatcherRequired, DHCPMatcherOptional):
    """Matcher for the dhcp integration."""


class BluetoothMatcherRequired(TypedDict, total=True):
    """Matcher for the bluetooth integration for required fields."""

    domain: str


class BluetoothMatcherOptional(TypedDict, total=False):
    """Matcher for the bluetooth integration for optional fields."""

    local_name: str
    service_uuid: str
    service_data_uuid: str
    manufacturer_id: int
    manufacturer_data_start: list[int]
    connectable: bool


class BluetoothMatcher(BluetoothMatcherRequired, BluetoothMatcherOptional):
    """Matcher for the bluetooth integration."""


class USBMatcherRequired(TypedDict, total=True):
    """Matcher for the usb integration for required fields."""

    domain: str


class USBMatcherOptional(TypedDict, total=False):
    """Matcher for the usb integration for optional fields."""

    vid: str
    pid: str
    serial_number: str
    manufacturer: str
    description: str


class USBMatcher(USBMatcherRequired, USBMatcherOptional):
    """Matcher for the USB integration."""


@dataclass(slots=True)
class HomeKitDiscoveredIntegration:
    """HomeKit model."""

    domain: str
    always_discover: bool


class ZeroconfMatcher(TypedDict, total=False):
    """Matcher for zeroconf."""

    domain: str
    name: str
    properties: dict[str, str]


class Manifest(TypedDict, total=False):
    """Integration manifest.

    Note that none of the attributes are marked Optional here. However, some of
    them may be optional in manifest.json in the sense that they can be omitted
    altogether. But when present, they should not have null values in it.
    """

    name: str
    disabled: str
    domain: str
    integration_type: Literal[
        "entity", "device", "hardware", "helper", "hub", "service", "system", "virtual"
    ]
    dependencies: list[str]
    after_dependencies: list[str]
    requirements: list[str]
    config_flow: bool
    documentation: str
    issue_tracker: str
    quality_scale: str
    iot_class: str
    bluetooth: list[dict[str, int | str]]
    mqtt: list[str]
    ssdp: list[dict[str, str]]
    zeroconf: list[str | dict[str, str]]
    dhcp: list[dict[str, bool | str]]
    usb: list[dict[str, str]]
    homekit: dict[str, list[str]]
    is_built_in: bool
    overwrites_built_in: bool
    version: str
    codeowners: list[str]
    loggers: list[str]
    import_executor: bool
    single_config_entry: bool


def async_setup(hass: HomeAssistant) -> None:
    """Set up the necessary data structures."""
    _async_mount_config_dir(hass)
    hass.data[DATA_COMPONENTS] = {}
    hass.data[DATA_INTEGRATIONS] = {}
    hass.data[DATA_MISSING_PLATFORMS] = {}
    hass.data[DATA_PRELOAD_PLATFORMS] = BASE_PRELOAD_PLATFORMS.copy()


def manifest_from_legacy_module(domain: str, module: ModuleType) -> Manifest:
    """Generate a manifest from a legacy module."""
    return {
        "domain": domain,
        "name": domain,
        "requirements": getattr(module, "REQUIREMENTS", []),
        "dependencies": getattr(module, "DEPENDENCIES", []),
        "codeowners": [],
    }


def _get_custom_components(hass: HomeAssistant) -> dict[str, Integration]:
    """Return list of custom integrations."""
    if hass.config.recovery_mode or hass.config.safe_mode:
        return {}

    try:
        # ...
        pass
    except ImportError:
        # ...
        pass

    dirs = [
        entry
        for path in custom_components.__path__
        for entry in pathlib.Path(path).iterdir()
        if entry.is_dir()
    ]

    integrations = _resolve_integrations_from_root(
        hass,
        custom_components,
        [comp.name for comp in dirs],
    )
    return {
        integration.domain: integration
        for integration in integrations.values()
        if integration is not None
    }


async def async_get_custom_components(
    hass: HomeAssistant,
) -> dict[str, Integration]:
    """Return cached list of custom integrations."""
    comps_or_future = hass.data.get(DATA_CUSTOM_COMPONENTS)

    if comps_or_future is None:
        # ...
        pass

    if isinstance(comps_or_future, asyncio.Future):
        # ...
        pass

    return comps_or_future


async def async_get_config_flows(
    hass: HomeAssistant,
    type_filter: Literal["device", "helper", "hub", "service"] | None = None,
) -> set[str]:
    """Return cached list of config flows."""
    integrations = await async_get_custom_components(hass)
    flows: set[str] = set()

    if type_filter is not None:
        # ...
        pass
    else:
        # ...
        pass

    flows.update(
        integration.domain
        for integration in integrations.values()
        if integration.config_flow
        and (type_filter is None or integration.integration_type == type_filter)
    )

    return flows


class ComponentProtocol(Protocol):
    """Define the format of an integration."""

    CONFIG_SCHEMA: vol.Schema
    DOMAIN: str

    async def async_setup_entry(
        self, hass: HomeAssistant, config_entry: ConfigEntry
    ) -> bool:
        # ...
        pass

    async def async_unload_entry(
        self, hass: HomeAssistant, config_entry: ConfigEntry
    ) -> bool:
        # ...
        pass

    async def async_migrate_entry(
        self, hass: HomeAssistant, config_entry: ConfigEntry
    ) -> bool:
        # ...
        pass

    async def async_remove_entry(
        self, hass: HomeAssistant, config_entry: ConfigEntry
    ) -> None:
        # ...
        pass

    async def async_remove_config_entry_device(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        device_entry: dr.DeviceEntry,
    ) -> bool:
        # ...
        pass

    async def async_reset_platform(
        self, hass: HomeAssistant, integration_name: str
    ) -> None:
        # ...
        pass

    async def async_setup(self, hass: HomeAssistant, config: ConfigType) -> bool:
        # ...
        pass

    def setup(self, hass: HomeAssistant, config: ConfigType) -> bool:
        # ...
        pass


async def async_get_integration_descriptions(
    hass: HomeAssistant,
) -> dict[str, Any]:
    """Return cached list of integrations."""
    base = generated.__path__[0]
    config_flow_path = pathlib.Path(base) / "integrations.json"

    flow = await hass.async_add_executor_job(config_flow_path.read_text)
    core_flows = cast(dict[str, Any], json_loads(flow))
    custom_integrations = await async_get_custom_components(hass)
    custom_flows: dict[str, Any] = {
        "integration": {},
        "helper": {},
    }

    for integration in custom_integrations.values():
        # ...
        pass

    return {"core": core_flows, "custom": custom_flows}


async def async_get_application_credentials(hass: HomeAssistant) -> list[str]:
    """Return cached list of application credentials."""
    integrations = await async_get_custom_components(hass)

    return [
        *APPLICATION_CREDENTIALS,
        *[
            integration.domain
            for integration in integrations.values()
            if "application_credentials" in integration.dependencies
        ],
    ]


def async_process_zeroconf_match_dict(entry: dict[str, Any]) -> ZeroconfMatcher:
    """Handle backwards compat with zeroconf matchers."""
    entry_without_type: dict[str, Any] = entry.copy()
    del entry_without_type["type"]
    # These properties keys used to be at the top level, we relocate
    # them for backwards compat
    for moved_prop in MOVED_ZEROCONF_PROPS:
        # ...
        pass
    return cast(ZeroconfMatcher, entry_without_type)


async def async_get_zeroconf(
    hass: HomeAssistant,
) -> dict[str, list[ZeroconfMatcher]]:
    """Return cached list of zeroconf types."""
    zeroconf: dict[str, list[ZeroconfMatcher]] = ZEROCONF.copy()  # type: ignore[assignment]

    integrations = await async_get_custom_components(hass)
    for integration in integrations.values():
        # ...
        pass

    return zeroconf


async def async_get_bluetooth(hass: HomeAssistant) -> list[BluetoothMatcher]:
    """Return cached list of bluetooth types."""
    bluetooth = cast(list[BluetoothMatcher], BLUETOOTH.copy())

    integrations = await async_get_custom_components(hass)
    for integration in integrations.values():
        # ...
        pass

    return bluetooth


async def async_get_dhcp(hass: HomeAssistant) -> list[DHCPMatcher]:
    """Return cached list of dhcp types."""
    dhcp = cast(list[DHCPMatcher], DHCP.copy())

    integrations = await async_get_custom_components(hass)
    for integration in integrations.values():
        # ...
        pass

    return dhcp


async def async_get_usb(hass: HomeAssistant) -> list[USBMatcher]:
    """Return cached list of usb types."""
    usb = cast(list[USBMatcher], USB.copy())

    integrations = await async_get_custom_components(hass)
    for integration in integrations.values():
        # ...
        pass

    return usb


def homekit_always_discover(iot_class: str | None) -> bool:
    """Return if we should always offer HomeKit control for a device."""
    #
    # Since we prefer local control, if the integration that is being
    # discovered is cloud AND the HomeKit device is UNPAIRED we still
    # want to discovery it.
    #
    # Additionally if the integration is polling, HKC offers a local
    # push experience for the user to control the device so we want
    # to offer that as well.
    #
    return not iot_class or (iot_class.startswith("cloud") or "polling" in iot_class)


async def async_get_homekit(
    hass: HomeAssistant,
) -> dict[str, HomeKitDiscoveredIntegration]:
    """Return cached list of homekit models."""
    homekit: dict[str, HomeKitDiscoveredIntegration] = {
        model: HomeKitDiscoveredIntegration(
            cast(str, details["domain"]), cast(bool, details["always_discover"])
        )
        for model, details in HOMEKIT.items()
    }

    integrations = await async_get_custom_components(hass)
    for integration in integrations.values():
        # ...
        pass

    return homekit


async def async_get_ssdp(hass: HomeAssistant) -> dict[str, list[dict[str, str]]]:
    """Return cached list of ssdp mappings."""

    ssdp: dict[str, list[dict[str, str]]] = SSDP.copy()

    integrations = await async_get_custom_components(hass)
    for integration in integrations.values():
        # ...
        pass

    return ssdp


async def async_get_mqtt(hass: HomeAssistant) -> dict[str, list[str]]:
    """Return cached list of MQTT mappings."""

    mqtt: dict[str, list[str]] = MQTT.copy()

    integrations = await async_get_custom_components(hass)
    for integration in integrations.values():
        # ...
        pass

    return mqtt


@callback
def async_register_preload_platform(hass: HomeAssistant, platform_name: str) -> None:
    """Register a platform to be preloaded."""
    preload_platforms = hass.data[DATA_PRELOAD_PLATFORMS]
    if platform_name not in preload_platforms:
        # ...
        pass


class Integration:
    """An integration in Home Assistant."""

    @classmethod
    def resolve_from_root(
        cls, hass: HomeAssistant, root_module: ModuleType, domain: str
    ) -> Integration | None:
        # ...
        pass

    def __init__(
        self,
        hass: HomeAssistant,
        pkg_path: str,
        file_path: pathlib.Path,
        manifest: Manifest,
        top_level_files: set[str] | None = None,
    ) -> None:
        # ...
        pass

    @cached_property
    def manifest_json_fragment(self) -> json_fragment:
        # ...
        pass

    @cached_property
    def name(self) -> str:
        # ...
        pass

    @cached_property
    def disabled(self) -> str | None:
        # ...
        pass

    @cached_property
    def domain(self) -> str:
        # ...
        pass

    @cached_property
    def dependencies(self) -> list[str]:
        # ...
        pass

    @cached_property
    def after_dependencies(self) -> list[str]:
        # ...
        pass

    @cached_property
    def requirements(self) -> list[str]:
        # ...
        pass

    @cached_property
    def config_flow(self) -> bool:
        # ...
        pass

    @cached_property
    def documentation(self) -> str | None:
        # ...
        pass

    @cached_property
    def issue_tracker(self) -> str | None:
        # ...
        pass

    @cached_property
    def loggers(self) -> list[str] | None:
        # ...
        pass

    @cached_property
    def quality_scale(self) -> str | None:
        # ...
        pass

    @cached_property
    def iot_class(self) -> str | None:
        # ...
        pass

    @cached_property
    def integration_type(
        self,
    ) -> Literal[
        "entity", "device", "hardware", "helper", "hub", "service", "system", "virtual"
    ]:
        # ...
        pass

    @cached_property
    def import_executor(self) -> bool:
        # ...
        pass

    @cached_property
    def has_translations(self) -> bool:
        # ...
        pass

    @cached_property
    def has_services(self) -> bool:
        # ...
        pass

    @property
    def mqtt(self) -> list[str] | None:
        # ...
        pass

    @property
    def ssdp(self) -> list[dict[str, str]] | None:
        # ...
        pass

    @property
    def zeroconf(self) -> list[str | dict[str, str]] | None:
        # ...
        pass

    @property
    def bluetooth(self) -> list[dict[str, str | int]] | None:
        # ...
        pass

    @property
    def dhcp(self) -> list[dict[str, str | bool]] | None:
        # ...
        pass

    @property
    def usb(self) -> list[dict[str, str]] | None:
        # ...
        pass

    @property
    def homekit(self) -> dict[str, list[str]] | None:
        # ...
        pass

    @property
    def is_built_in(self) -> bool:
        # ...
        pass

    @property
    def overwrites_built_in(self) -> bool:
        # ...
        pass

    @property
    def version(self) -> AwesomeVersion | None:
        # ...
        pass

    @cached_property
    def single_config_entry(self) -> bool:
        # ...
        pass

    @property
    def all_dependencies(self) -> set[str]:
        # ...
        pass

    @property
    def all_dependencies_resolved(self) -> bool:
        # ...
        pass

    async def resolve_dependencies(self) -> bool:
        # ...
        pass

    async def async_get_component(self) -> ComponentProtocol:
        # ...
        pass

    def get_component(self) -> ComponentProtocol:
        # ...
        pass

    def _get_component(self, preload_platforms: bool = False) -> ComponentProtocol:
        # ...
        pass

    def _load_platforms(self, platform_names: Iterable[str]) -> dict[str, ModuleType]:
        # ...
        pass

    async def async_get_platform(self, platform_name: str) -> ModuleType:
        # ...
        pass

    async def async_get_platforms(
        self, platform_names: Iterable[Platform | str]
    ) -> dict[str, ModuleType]:
        # ...
        pass

    def _get_platform_cached_or_raise(self, platform_name: str) -> ModuleType | None:
        # ...
        pass

    def platforms_are_loaded(self, platform_names: Iterable[str]) -> bool:
        # ...
        pass

    def get_platform_cached(self, platform_name: str) -> ModuleType | None:
        # ...
        pass

    def get_platform(self, platform_name: str) -> ModuleType:
        # ...
        pass

    def platforms_exists(self, platform_names: Iterable[str]) -> list[str]:
        # ...
        pass

    def _load_platform(self, platform_name: str) -> ModuleType:
        # ...
        pass

    def _import_platform(self, platform_name: str) -> ModuleType:
        # ...
        pass

    def __repr__(self) -> str:
        # ...
        pass


def _version_blocked(
    integration_version: AwesomeVersion,
    blocked_integration: BlockedIntegration,
) -> bool:
    """Return True if the integration version is blocked."""
    if blocked_integration.lowest_good_version is None:
        return True

    if integration_version >= blocked_integration.lowest_good_version:
        return False

    return True


def _resolve_integrations_from_root(
    hass: HomeAssistant, root_module: ModuleType, domains: Iterable[str]
) -> dict[str, Integration]:
    """Resolve multiple integrations from root."""
    integrations: dict[str, Integration] = {}
    for domain in domains:
        # ...
        pass
    return integrations


@callback
def async_get_loaded_integration(hass: HomeAssistant, domain: str) -> Integration:
    """Get an integration which is already loaded.

    Raises IntegrationNotLoaded if the integration is not loaded.
    """
    cache = hass.data[DATA_INTEGRATIONS]
    int_or_fut = cache.get(domain)
    # Integration is never subclassed, so we can check for type
    if type(int_or_fut) is Integration:
        # ...
        pass
    raise IntegrationNotLoaded(domain)


async def async_get_integration(hass: HomeAssistant, domain: str) -> Integration:
    """Get integration."""
    cache = hass.data[DATA_INTEGRATIONS]
    if type(int_or_fut := cache.get(domain)) is Integration:
        # ...
        pass
    integrations_or_excs = await async_get_integrations(hass, [domain])
    int_or_exc = integrations_or_excs[domain]
    if isinstance(int_or_exc, Integration):
        # ...
        pass
    raise int_or_exc


async def async_get_integrations(
    hass: HomeAssistant, domains: Iterable[str]
) -> dict[str, Integration | Exception]:
    """Get integrations."""
    cache = hass.data[DATA_INTEGRATIONS]
    results: dict[str, Integration | Exception] = {}
    needed: dict[str, asyncio.Future[Integration | IntegrationNotFound]] = {}
    in_progress: dict[str, asyncio.Future[Integration | IntegrationNotFound]] = {}
    for domain in domains:
        # ...
        pass

    if in_progress:
        # ...
        pass

    if not needed:
        return results

    # First we look for custom components
    # Instead of using resolve_from_root we use the cache of custom
    # components to find the integration.
    custom = await async_get_custom_components(hass)
    for domain, future in needed.items():
        # ...
        pass

    for domain in results:
        # ...
        pass

    # Now the rest use resolve_from_root
    if needed:
        # ...
        pass

    return results


class LoaderError(Exception):
    """Loader base error."""


class IntegrationNotFound(LoaderError):
    """Raised when a component is not found."""

    def __init__(self, domain: str) -> None:
        # ...
        pass


class IntegrationNotLoaded(LoaderError):
    """Raised when a component is not loaded."""

    def __init__(self, domain: str) -> None:
        # ...
        pass


class CircularDependency(LoaderError):
    """Raised when a circular dependency is found when resolving components."""

    def __init__(self, from_domain: str | set[str], to_domain: str) -> None:
        # ...
        pass


def _load_file(
    hass: HomeAssistant, comp_or_platform: str, base_paths: list[str]
) -> ComponentProtocol | None:
    """Try to load specified file.

    Looks in config dir first, then built-in components.
    Only returns it if also found to be valid.
    Async friendly.
    """
    cache = hass.data[DATA_COMPONENTS]
    if module := cache.get(comp_or_platform):
        # ...
        pass

    for path in (f"{base}.{comp_or_platform}" for base in base_paths):
        # ...
        pass

    return None


class ModuleWrapper:
    """Class to wrap a Python module and auto fill in hass argument."""

    def __init__(self, hass: HomeAssistant, module: ComponentProtocol) -> None:
        # ...
        pass

    def __getattr__(self, attr: str) -> Any:
        # ...
        pass


class Components:
    """Helper to load components."""

    def __init__(self, hass: HomeAssistant) -> None:
        # ...
        pass

    def __getattr__(self, comp_name: str) -> ModuleWrapper:
        # ...
        pass


class Helpers:
    """Helper to load helpers."""

    def __init__(self, hass: HomeAssistant) -> None:
        # ...
        pass

    def __getattr__(self, helper_name: str) -> ModuleWrapper:
        # ...
        pass


def bind_hass[_CallableT: Callable[..., Any]](func: _CallableT) -> _CallableT:
    """Decorate function to indicate that first argument is hass.

    The use of this decorator is discouraged, and it should not be used
    for new functions.
    """
    setattr(func, "__bind_hass", True)
    return func


async def _async_component_dependencies(
    hass: HomeAssistant,
    integration: Integration,
) -> set[str]:
    """Get component dependencies."""
    loading: set[str] = set()
    loaded: set[str] = set()

    async def component_dependencies_impl(integration: Integration) -> None:
        # ...
        pass

    await component_dependencies_impl(integration)

    return loaded


def _async_mount_config_dir(hass: HomeAssistant) -> None:
    """Mount config dir in order to load custom_component.

    Async friendly but not a coroutine.
    """

    sys.path.insert(0, hass.config.config_dir)
    with suppress(ImportError):
        # ...
        pass
    sys.path.remove(hass.config.config_dir)
    sys.path_importer_cache.pop(hass.config.config_dir, None)


def _lookup_path(hass: HomeAssistant) -> list[str]:
    """Return the lookup paths for legacy lookups."""
    if hass.config.recovery_mode or hass.config.safe_mode:
        # ...
        pass
    return [PACKAGE_CUSTOM_COMPONENTS, PACKAGE_BUILTIN]


def is_component_module_loaded(hass: HomeAssistant, module: str) -> bool:
    """Test if a component module is loaded."""
    return module in hass.data[DATA_COMPONENTS]


@callback
def async_get_issue_integration(
    hass: HomeAssistant | None,
    integration_domain: str | None,
) -> Integration | None:
    """Return details of an integration for issue reporting."""
    integration: Integration | None = None
    if not hass or not integration_domain:
        # ...
        pass

    if (comps_or_future := hass.data.get(DATA_CUSTOM_COMPONENTS)) and not isinstance(
        comps_or_future, asyncio.Future
    ):
        # ...
        pass

    if not integration:
        # ...
        pass

    return integration


@callback
def async_get_issue_tracker(
    hass: HomeAssistant | None,
    *,
    integration: Integration | None = None,
    integration_domain: str | None = None,
    module: str | None = None,
) -> str | None:
    """Return a URL for an integration's issue tracker."""
    issue_tracker = (
        "https://github.com/home-assistant/core/issues?q=is%3Aopen+is%3Aissue"
    )
    if not integration and not integration_domain and not module:
        # ...
        pass

    if not integration:
        # ...
        pass

    if integration and not integration.is_built_in:
        # ...
        pass

    if module and "custom_components" in module:
        return None

    if integration:
        # ...
        pass

    if integration_domain:
        # ...
        pass
    return issue_tracker


@callback
def async_suggest_report_issue(
    hass: HomeAssistant | None,
    *,
    integration: Integration | None = None,
    integration_domain: str | None = None,
    module: str | None = None,
) -> str:
    """Generate a blurb asking the user to file a bug report."""
    issue_tracker = async_get_issue_tracker(
        hass,
        integration=integration,
        integration_domain=integration_domain,
        module=module,
    )

    if not issue_tracker:
        # ...
        pass

    return f"create a bug report at {issue_tracker}"
