package org.cloudfoundry.identity.uaa.util;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * DNS resolver that delegates to the system resolver and then rejects any address
 * that falls in a private, loopback, link-local, or cloud-metadata range.
 *
 * Used as the DnsResolver for the RestTemplate that fetches client jwks_uri content,
 * providing defense-in-depth against DNS rebinding after jwks_uri validation.
 */
public class PrivateNetworkBlockingDnsResolver implements DnsResolver {

    public static final PrivateNetworkBlockingDnsResolver INSTANCE = new PrivateNetworkBlockingDnsResolver();

    private static final DnsResolver DELEGATE = SystemDefaultDnsResolver.INSTANCE;

    private PrivateNetworkBlockingDnsResolver() {}

    @Override
    public InetAddress[] resolve(String host) throws UnknownHostException {
        InetAddress[] addresses = DELEGATE.resolve(host);
        InetAddress blocked = Arrays.stream(addresses)
                .filter(PrivateNetworkGuard::isBlocked)
                .findFirst()
                .orElse(null);
        if (blocked != null) {
            throw new UnknownHostException(
                    "Host " + host + " resolves to a blocked address: " + blocked.getHostAddress());
        }
        return addresses;
    }

    @Override
    public String resolveCanonicalHostname(String host) throws UnknownHostException {
        return DELEGATE.resolveCanonicalHostname(host);
    }
}
