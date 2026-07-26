package org.cloudfoundry.identity.uaa.util;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * Rejects hostnames that resolve to private, loopback, link-local, or cloud-metadata
 * IP ranges. Used to prevent SSRF via operator-supplied fetch targets such as jwks_uri.
 */
public final class PrivateNetworkGuard {

    // AWS/GCP/Azure instance-metadata address
    private static final byte[] METADATA_V4 = {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
    private PrivateNetworkGuard() {}

    /**
     * Resolves all addresses for the host in {@code uri} and throws if any of them
     * fall into a private, loopback, link-local, or well-known metadata range.
     *
     * @throws IllegalArgumentException if the host resolves to a blocked address
     * @throws UnknownHostException     if DNS resolution fails
     */
    public static void assertPublic(URI uri) throws UnknownHostException {
        String host = uri.getHost();
        if (host == null) {
            throw new IllegalArgumentException("URI has no host: " + uri);
        }
        for (InetAddress addr : InetAddress.getAllByName(host)) {
            if (isBlocked(addr)) {
                throw new IllegalArgumentException(
                        "jwks_uri host resolves to a blocked (private/loopback/link-local) address: " + addr.getHostAddress());
            }
        }
    }

    /**
     * Returns true if the address must be blocked as an outbound fetch target.
     */
    public static boolean isBlocked(InetAddress addr) {
        if (addr.isLoopbackAddress()) {
            return true;
        }
        if (addr.isLinkLocalAddress()) {
            return true;
        }
        if (addr.isSiteLocalAddress()) {
            return true;
        }
        if (addr.isMulticastAddress()) {
            return true;
        }
        byte[] raw = addr.getAddress();
        // 169.254.169.254 — cloud instance-metadata (IPv4)
        if (raw.length == 4 && raw[0] == METADATA_V4[0] && raw[1] == METADATA_V4[1]
                && raw[2] == METADATA_V4[2] && raw[3] == METADATA_V4[3]) {
            return true;
        }
        // Unspecified / any-local (0.0.0.0 or ::)
        if (addr.isAnyLocalAddress()) {
            return true;
        }
        // IPv6 unique-local (fc00::/7)
        return (raw.length == 16 && (raw[0] & 0xfe) == 0xfc);
    }
}
