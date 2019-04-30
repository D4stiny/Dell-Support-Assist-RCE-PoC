import ifaddr


def get_ip_address(interface_name):
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        if adapter.name == interface_name or adapter.nice_name == interface_name:
            for ip in adapter.ips:
                if ":" not in ip.ip[0]:  # We only want ipv4
                    return ip.ip

    return "0.0.0.0"
