const PROTOCOLS_AND_PORTS = {
    "ftp:": 20,
    "ssh:": 22,
    "smtp:": 25,
    "dns:": 53,
    "dhcp:": 67,
    "tftp:": 69, // nice
    "http:": 80,
    "pop:": 110,
    "ntp:": 123,
    "imap:": 143,
    "snmp:": 161,
    "bgp:": 179,
    "ldap:": 389,
    "https:": 443,
    "ldaps:": 636
}

export const getPortForProtocol = (protocol) => {
    const lowercase_protocol_string = `${protocol}`.toLowerCase();
    return PROTOCOLS_AND_PORTS[lowercase_protocol_string];
}