#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2018 Florian Tautz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
from typing import Tuple, Sequence, Mapping

import toml
from netaddr import IPAddress, IPNetwork
from pylxd import Client


def format_address(address: IPAddress) -> str:
    return "[{0}]".format(address) if address.version == 6 else str(address)


def generate_forwarding_rules(addresses: Mapping[str, Sequence[IPAddress]],
                              ports: Mapping[str, Tuple[str, int, int]],
                              host_interface: str) -> Sequence[str]:
    rules = []

    for name, addresses in addresses.items():
        for protocol, from_port, to_port in ports[name]:
            for address in addresses:
                iptables = "ip6tables" if address.version == 6 else "iptables"
                rules.append("{iptables} -t nat -A PREROUTING "
                             "-i {host_if} -p {proto} --dport {from_port} "
                             "-j DNAT --to-destination {address}:{to_port}"
                             .format(host_if=host_interface, proto=protocol,
                                     from_port=from_port, to_port=to_port,
                                     address=format_address(address),
                                     iptables=iptables))

    return rules


def apply_rules(rules: Sequence[str]) -> None:
    for rule in rules:
        os.system(rule)


def get_container_addresses(lxd_client: Client, container_names: Sequence[str],
                            bridge_networks: Sequence[IPNetwork]) -> Mapping[str, Sequence[IPAddress]]:
    result = dict()

    for name in container_names:
        container = lxd_client.containers.get(name)
        interfaces = container.state().network.values()
        addresses = [IPAddress(addr['address']) for iface in interfaces for addr in iface['addresses']]
        result[name] = [addr for addr in addresses
                        if any(addr in net for net in bridge_networks)]

    return result


def main():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("config")
    parser.add_argument("--bridge-config", default="/etc/default/lxd-bridge")
    args = parser.parse_args()

    config = toml.load(args.config)
    bridge_cfg = toml.load(args.bridge_config)

    bridge_networks = [IPNetwork(bridge_cfg["LXD_IPV{0}_NETWORK".format(ipv)]) for ipv in [4, 6]]

    def maybe_get(dic, key, default, type=None):
        try:
            value = dic[key]
            return type(value) if type is not None else value
        except KeyError:
            return default

    general_cfg = config['general']
    client_params = {
        'endpoint': maybe_get(general_cfg, 'endpoint', None),
        'cert': maybe_get(general_cfg, 'certificate', None, tuple),
        'verify': maybe_get(general_cfg, 'https_verify', True),
    }
    lxd_client = Client(**client_params)

    container_names = [container["name"] for container in config["container"]]
    container_addresses = get_container_addresses(lxd_client, container_names, bridge_networks)

    container_ports = {container["name"]: [(port["protocol"], port["from"], port["to"])
                                           for port in container["port"]]
                       for container in config["container"]}
    rules = generate_forwarding_rules(container_addresses, container_ports, config["general"]["host_interface"])

    apply_rules(rules)


if __name__ == '__main__':
    main()
