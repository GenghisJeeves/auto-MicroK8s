import logging
import time
from typing import Literal

from sdbus import DbusInterfaceCommon, dbus_method, sd_bus_open_system

logger = logging.getLogger(__name__)

ServiceProtocol = Literal[0, 1]  # 0=IPv4, 1=IPv6
NetworkInterface = int  # -1=Any Interface
ServiceFlags = int  # 0=Default


class AvahiServerInterface(
    DbusInterfaceCommon, interface_name="org.freedesktop.Avahi.Server"
):
    @dbus_method()
    def Commit(self) -> None:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetVersionString(self) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetAPIVersion(self) -> int:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetHostName(self) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method(input_signature="s")
    def SetHostName(self, name: str) -> None:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetHostNameFqdn(self) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetDomainName(self) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def IsNSSSupportAvailable(self) -> bool:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetState(self) -> int:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetLocalServiceCookie(self) -> int:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetAlternativeHostName(self, name: str) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetAlternativeServiceName(self, name: str) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetNetworkInterfaceNameByIndex(self, index: int) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def GetNetworkInterfaceIndexByName(self, name: str) -> int:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def ResolveHostName(
        self,
        interface: int,
        protocol: int,
        name: str,
        aprotocol: int,
        flags: int,
    ) -> tuple[int, int, str, int, str, int]:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def ResolveAddress(
        self,
        interface: int,
        protocol: int,
        address: str,
        flags: int,
    ) -> tuple[int, int, int, str, str, int]:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def ResolveService(
        self,
        interface: int,
        protocol: int,
        name: str,
        type: str,
        domain: str,
        aprotocol: int,
        flags: int,
    ) -> tuple[int, int, str, str, str, str, int, str, int, list[bytes], int]:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method(input_signature="iiussssqaay")
    def EntryGroupNew(
        self,
        interface: int,
        protocol: int,
        flags: int,
        name: str,
        type: str,
        domain: str,
        host: str,
        port: int,
        txt: list[bytes],
    ) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def DomainBrowserNew(
        self,
        interface: int,
        protocol: int,
        domain: str,
        btype: int,
        flags: int,
    ) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def ServiceTypeBrowserNew(
        self,
        interface: int,
        protocol: int,
        domain: str,
        flags: int,
    ) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method(input_signature="iissu")
    def ServiceBrowserNew(
        self,
        interface: int,
        protocol: int,
        type: str,
        domain: str,
        flags: int,
    ) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def ServiceResolverNew(
        self,
        interface: int,
        protocol: int,
        name: str,
        type: str,
        domain: str,
        aprotocol: int,
        flags: int,
    ) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def HostNameResolverNew(
        self,
        interface: int,
        protocol: int,
        name: str,
        aprotocol: int,
        flags: int,
    ) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def AddressResolverNew(
        self,
        interface: int,
        protocol: int,
        address: str,
        flags: int,
    ) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )

    @dbus_method()
    def RecordBrowserNew(
        self,
        interface: int,
        protocol: int,
        name: str,
        clazz: int,
        type: int,
        flags: int,
    ) -> str:
        raise NotImplementedError(
            "This method should be implemented by the D-Bus binding."
        )


def set_hostname(hostname: str) -> bool:
    try:
        bus = sd_bus_open_system()
    except Exception as e:
        logger.error(f"Failed to connect to system bus: {e}")
        return False

    try:
        avahi_server = AvahiServerInterface(
            "org.freedesktop.Avahi",
            "/",
            bus,
        )
        avahi_server.SetHostName(hostname)
        logger.info(f"Hostname set to: {hostname}")
        return True
    except Exception as e:
        logger.error(f"Failed to set hostname: {e}")
        return False


def check_hostname(hostname: str) -> bool:
    try:
        bus = sd_bus_open_system()
    except Exception as e:
        logger.error(f"Failed to connect to system bus: {e}")
        return False

    try:
        avahi_server = AvahiServerInterface(
            "org.freedesktop.Avahi",
            "/",
            bus,
        )
        current_hostname = avahi_server.GetHostName()
        if current_hostname == hostname:
            logger.info(f"Hostname is correctly set to: {current_hostname}")
            return True
        else:
            logger.warning(
                f"Hostname mismatch: expected '{hostname}', got '{current_hostname}'"
            )
            return False
    except Exception as e:
        logger.error(f"Failed to check hostname: {e}")
        return False


def register_avahi_service(service_name: str, service_type: str, port: int) -> bool:
    try:
        bus = sd_bus_open_system()
    except Exception as e:
        logger.error(f"Failed to connect to system bus: {e}")
        return False

    try:
        avahi_server = AvahiServerInterface(
            "org.freedesktop.Avahi",
            "/",
            bus,
        )

        # Get Avahi version string first
        try:
            version = avahi_server.GetVersionString()
            logger.info(f"Avahi daemon version: {version}")
        except Exception as e:
            logger.warning(f"Could not get Avahi version: {e}")

        # Get Avahi API version
        try:
            api_version = avahi_server.GetAPIVersion()
            logger.info(f"Avahi API version: {api_version}")
        except Exception as e:
            logger.warning(f"Could not get Avahi API version: {e}")

        # Get State of Avahi server
        try:
            state = avahi_server.GetState()
            logger.info(f"Avahi server state: {state}")
        except Exception as e:
            logger.warning(f"Could not get Avahi server state: {e}")

        # Create ServiceBrowserNew for HTTP service
        service_browser = avahi_server.ServiceBrowserNew(
            interface=-1,  # -1 for all interfaces
            protocol=-1,  # -1 for both IPv4 and IPv6
            type=service_type,
            domain="",  # Use default domain
            flags=0,  # Default flags
        )
        logger.info(f"Service browser created: {service_browser}")

        entry_group = avahi_server.EntryGroupNew(
            interface=-1,
            protocol=-0,  # -1 for both IPv4 and IPv6
            flags=0,
            name=service_name,
            type=service_type,
            domain="",  # Use default domain
            host="",
            port=port,
            txt=[b"path=/"],  # No TXT records
        )

        #     entry_group.commit()
        time.sleep(0.5)  # Allow time for registration
        logger.info(f"Service '{service_name}' registered as {entry_group}")

        # View the entry group
        entry_group_proxy = AvahiServerInterface(
            "org.freedesktop.Avahi.EntryGroup",
            entry_group,
            bus,
        )
        logger.info(f"Entry group created: {entry_group_proxy}")

        entry_group_proxy.Commit

        # Get Services
        services = avahi_server.ServiceBrowserNew(
            interface=-1,  # -1 for all interfaces
            protocol=-1,  # -1 for both IPv4 and IPv6
            type=service_type,
            domain="",  # Use default domain
            flags=0,  # Default flags
        )
        logger.info(f"Service browser created: {services}")
        logger.info(
            f"Service '{service_name}' of type '{service_type}' registered on port {port}."
        )
        logger.info("Avahi service registration complete.")
        # Commit the entry group to finalize the service registration
        entry_group_proxy.Commit()

        # Get Services
        services = avahi_server.ServiceBrowserNew(
            interface=-1,  # -1 for all interfaces
            protocol=-1,  # -1 for both IPv4 and IPv6
            type=service_type,
            domain="",  # Use default domain
            flags=0,  # Default flags
        )
        logger.info(f"Service browser created: {services}")
        logger.info(
            f"Service '{service_name}' of type '{service_type}' registered on port {port}."
        )
        logger.info("Avahi service registration complete.")

        return True
    except Exception as e:
        logger.error(f"Failed to register service: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    register_avahi_service("avahi-test-web-advertise", "_http._tcp", 8080)
