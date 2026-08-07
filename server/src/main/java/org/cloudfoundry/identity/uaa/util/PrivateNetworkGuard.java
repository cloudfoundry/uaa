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
    // RFC 6598 — Carrier-grade NAT (100.64.0.0/10)
    private static final int RFC6598_START = (100 << 24) | (64 << 16);
    private static final int RFC6598_END   = (100 << 24) | (127 << 16) | (255 << 8) | 255;
    // IPv4-mapped IPv6 prefix: ::ffff:0:0/96
    private static final byte[] IPV4_MAPPED_PREFIX = {0,0, 0,0, 0,0, 0,0, 0,0, (byte)0xff,(byte)0xff};
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
        if (raw.length == 16 && (raw[0] & 0xfe) == 0xfc) {
            return true;
        }
        // RFC 6598 — carrier-grade NAT (100.64.0.0/10)
        if (raw.length == 4) {
            int ip = ((raw[0] & 0xff) << 24) | ((raw[1] & 0xff) << 16) | ((raw[2] & 0xff) << 8) | (raw[3] & 0xff);
            if (ip >= RFC6598_START && ip <= RFC6598_END) {
                return true;
            }
        }
        // IPv4-mapped IPv6 (::ffff:x.y.z.w) — check the embedded IPv4 part
        if (raw.length == 16) {
            boolean isMapped = true;
            for (int i = 0; i < IPV4_MAPPED_PREFIX.length; i++) {
                if (raw[i] != IPV4_MAPPED_PREFIX[i]) {
                    isMapped = false;
                    break;
                }
            }
            if (isMapped) {
                byte[] v4 = {raw[12], raw[13], raw[14], raw[15]};
                try {
                    return isBlocked(java.net.InetAddress.getByAddress(v4));
                } catch (java.net.UnknownHostException ignored) {
                    return true;
                }
            }
        }
        return false;
    }
}
