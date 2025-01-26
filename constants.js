const PROTOCOLS_AND_PORTS = {
    "ftp:": 20,
    "ssh:": 22,
    "tftp:": 69, // nice
    "http:": 80,
    "https:": 443
}

const getPortForProtocol = (protocol) => {
    const lowercase_protocol_string = `${protocol}`.toLowerCase();
    return PROTOCOLS_AND_PORTS[lowercase_protocol_string];
}