"""
Network information collectors.
"""

import os
import re
from .base import BaseCollector, CollectorResult, CollectorCategory
from ..utils.commands import run_command, safe_read_file, split_lines


class NetworkConfigCollector(BaseCollector):
    """Collect network configuration and interface information."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.NETWORK

    def collect(self) -> CollectorResult:
        interfaces = run_command(["networksetup", "-listallhardwareports"])

        # Get active network services.
        # Output format: "(1) Wi-Fi", "(2) Ethernet", disabled: "(*) Service"
        network_services = run_command(["networksetup", "-listnetworkserviceorder"])
        network_services_list = split_lines(network_services)
        active_services = []
        for line in network_services_list:
            # Match numbered entries like "(1) Wi-Fi" but skip disabled "(*) ..."
            m = re.match(r"^\((\d+)\)\s+(.+)$", line.strip())
            if m:
                active_services.append(m.group(2))

        ip_addresses = {}
        for service in active_services:
            ip = run_command(["ipconfig", "getifaddr", service])
            if ip:
                ip_addresses[service] = ip

        dns_result = run_command(["scutil", "--dns"])
        dns_servers_list = split_lines(dns_result)
        dns_servers = [line for line in dns_servers_list if "nameserver[" in line]

        routing_table = run_command(["netstat", "-nr"])
        arp_cache = run_command(["arp", "-a"])

        # WiFi info
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        wifi_networks = run_command([airport_path, "-s"])

        vpn = run_command(["networksetup", "-listpppoeservices"])

        # Proxy settings
        proxy_settings = {}
        for service in active_services:
            web_proxy = run_command(["networksetup", "-getwebproxy", service])
            secure_proxy = run_command(["networksetup", "-getsecurewebproxy", service])
            proxy_settings[service] = {
                "web_proxy": web_proxy if web_proxy else "",
                "secure_proxy": secure_proxy if secure_proxy else "",
            }

        firewall_status = run_command(
            ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"]
        )

        data = {
            "interfaces": split_lines(interfaces),
            "active_services": active_services,
            "ip_addresses": ip_addresses,
            "dns_servers": dns_servers,
            "routing_table": split_lines(routing_table),
            "arp_cache": split_lines(arp_cache),
            "wifi_networks": split_lines(wifi_networks),
            "vpn": split_lines(vpn),
            "proxy_settings": proxy_settings,
            "firewall_status": firewall_status if firewall_status else "",
        }

        return CollectorResult(success=True, data=data, collector_name=self.name)


class OpenPortsCollector(BaseCollector):
    """Collect open ports (non-privileged lsof)."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.NETWORK

    def collect(self) -> CollectorResult:
        # Use non-privileged lsof (shows user processes only)
        result = run_command(["lsof", "-i", "-P", "-n"])
        data = split_lines(result)

        return CollectorResult(success=True, data=data, collector_name=self.name)


class NetworkConnectionsCollector(BaseCollector):
    """Collect active network connections."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.NETWORK

    def collect(self) -> CollectorResult:
        result = run_command(["netstat", "-an"])
        data = split_lines(result)

        return CollectorResult(success=True, data=data, collector_name=self.name)


class SSHConfigCollector(BaseCollector):
    """Collect SSH configuration."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.NETWORK

    def collect(self) -> CollectorResult:
        ssh_config = safe_read_file("/etc/ssh/sshd_config")
        known_hosts = safe_read_file(os.path.expanduser("~/.ssh/known_hosts"))

        data = {
            "sshd_config": split_lines(ssh_config),
            "known_hosts": split_lines(known_hosts),
        }

        return CollectorResult(success=True, data=data, collector_name=self.name)


class HostsFileCollector(BaseCollector):
    """Collect /etc/hosts file contents."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.NETWORK

    def collect(self) -> CollectorResult:
        result = safe_read_file("/etc/hosts")
        data = split_lines(result)

        return CollectorResult(success=True, data=data, collector_name=self.name)


class NetworkSharesCollector(BaseCollector):
    """Collect network shares."""

    def __init__(self):
        super().__init__()
        self.category = CollectorCategory.NETWORK

    def collect(self) -> CollectorResult:
        result = run_command(["sharing", "-l"])
        data = split_lines(result)

        return CollectorResult(success=True, data=data, collector_name=self.name)


