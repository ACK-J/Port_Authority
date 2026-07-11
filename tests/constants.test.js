import { getPortForProtocol } from "../global/constants.js";
import { suite, assert, assertEqual } from "./harness.js";

export async function run() {
    suite("getPortForProtocol well-known mappings");
    assertEqual(getPortForProtocol("http:"), 80, "http");
    assertEqual(getPortForProtocol("https:"), 443, "https");
    assertEqual(getPortForProtocol("ws:"), 80, "ws");
    assertEqual(getPortForProtocol("wss:"), 443, "wss");
    assertEqual(getPortForProtocol("ftp:"), 20, "ftp");
    assertEqual(getPortForProtocol("ftps:"), 21, "ftps");
    assertEqual(getPortForProtocol("sftp:"), 22, "sftp");
    assertEqual(getPortForProtocol("ssh:"), 22, "ssh");
    assertEqual(getPortForProtocol("tftp:"), 69, "tftp");

    suite("getPortForProtocol normalization and unknowns");
    assertEqual(getPortForProtocol("HTTP:"), 80, "uppercase protocol");
    assertEqual(getPortForProtocol("Https:"), 443, "mixed case protocol");
    assertEqual(getPortForProtocol("WSS:"), 443, "uppercase wss");
    assertEqual(getPortForProtocol("gopher:"), undefined, "unknown protocol");
    assertEqual(getPortForProtocol(""), undefined, "empty string");
    assertEqual(getPortForProtocol(null), undefined, "null coerces then misses");
}
