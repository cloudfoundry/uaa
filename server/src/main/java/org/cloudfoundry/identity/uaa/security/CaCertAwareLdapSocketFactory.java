package org.cloudfoundry.identity.uaa.security;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * LDAP socket factory for zones whose LDAP IdP has {@code caCertificates} set. Deliberately does
 * NOT extend {@link BaseLdapSocketFactory}: that class (and {@link LdapSocketFactory}/
 * {@link SkipSslLdapSocketFactory}) bakes its trust decision into a single {@code delegate} built
 * once in the constructor -- fine for them, since "JDK default trust" and "trust everything" are the
 * same regardless of which zone is connecting. Per-IdP trust is not: JNDI resolves
 * {@code java.naming.ldap.factory.socket} via a reflective {@code getDefault()} call and caches
 * that one singleton instance for the life of the JVM, shared across every zone's LDAP connections.
 * A single fixed delegate here would mean whichever zone's caCertificates happened to be loaded
 * first wins forever. Instead, every {@code createSocket} call resolves the delegate dynamically
 * from the current zone (via {@link IdentityZoneHolder}, which is reliably set for the whole
 * bind/search call chain -- see {@code DynamicZoneAwareAuthenticationManager}) against a small
 * static registry populated by {@code DynamicLdapAuthenticationManager} whenever a zone's LDAP
 * config is (re)loaded.
 * <p>
 * Sockets are still wrapped in {@link HostnameAwareSslSocket} exactly as
 * {@link BaseLdapSocketFactory} does, so the hostname/SNI fix applies to these zones too -- see
 * {@link #wrap(Socket, String)}.
 */
public class CaCertAwareLdapSocketFactory extends SSLSocketFactory {

    private static final String ENDPOINT_ID_ALGORITHM = "LDAPS";
    private static final SocketFactory instance = new CaCertAwareLdapSocketFactory();

    private static final IdpOutboundTrustCache TRUST_CACHE = new IdpOutboundTrustCache();
    private static final ConcurrentMap<String, ZoneLdapTrust> ZONE_TRUST = new ConcurrentHashMap<>();

    public static SocketFactory getDefault() {
        return instance;
    }

    /**
     * Registers the given zone's current LDAP trust inputs. Must be called every time a zone's LDAP
     * IdP config is loaded or rebuilt (i.e. whenever the caller already has a fresh
     * {@code LdapIdentityProviderDefinition} in hand), so that a subsequent {@code createSocket} call
     * for this zone resolves the right trust material instead of a stale one.
     */
    public static void registerZoneTrust(String zoneId, List<String> caCertificates, boolean skipSslValidation) {
        ZONE_TRUST.put(zoneId, new ZoneLdapTrust(caCertificates, skipSslValidation));
    }

    private static SSLSocketFactory resolveDelegate() {
        String zoneId = IdentityZoneHolder.get().getId();
        ZoneLdapTrust trust = ZONE_TRUST.get(zoneId);
        if (trust == null) {
            // Defensive fallback only -- ProcessLdapProperties only selects this factory when
            // caCertificates is present, so a missing registry entry here would be a bug elsewhere,
            // not a real-world path. Fail safe to JDK-default trust rather than trusting nothing or
            // everything.
            return (SSLSocketFactory) LdapSocketFactory.getDefault();
        }
        SSLContext sslContext = TRUST_CACHE.resolveSslContext(zoneId, trust.caCertificates(), trust.skipSslValidation());
        return sslContext != null ? sslContext.getSocketFactory() : (SSLSocketFactory) LdapSocketFactory.getDefault();
    }

    /**
     * Wraps a freshly created socket so that a target hostname is always attached before the TLS
     * handshake starts, exactly as {@link BaseLdapSocketFactory} does for the other LDAP socket
     * factories. This matters for the no-arg {@link #createSocket()} overload, which JNDI uses
     * instead of {@code createSocket(host, port)} whenever {@code com.sun.jndi.ldap.connect.timeout}
     * is set (always, via {@code LdapIntegrationConfig}): JNDI creates an unconnected socket and
     * only supplies the hostname later via {@code connect(SocketAddress, int)}, which some JSSE
     * providers (observed with Bouncy Castle FIPS) do not infer the peer hostname from.
     * <p>
     * Sockets from the default-trust fallback are already wrapped by {@link BaseLdapSocketFactory},
     * so they are returned untouched rather than wrapped a second time.
     */
    private static Socket wrap(Socket socket, String knownHost) {
        if (socket instanceof HostnameAwareSslSocket) {
            return socket;
        }
        return new HostnameAwareSslSocket((SSLSocket) socket, ENDPOINT_ID_ALGORITHM, knownHost);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return resolveDelegate().getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return resolveDelegate().getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return wrap(resolveDelegate().createSocket(), null);
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return wrap(resolveDelegate().createSocket(socket, host, port, autoClose), host);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return wrap(resolveDelegate().createSocket(host, port), host);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
        return wrap(resolveDelegate().createSocket(host, port, localAddress, localPort), host);
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return wrap(resolveDelegate().createSocket(address, port), address.getHostName());
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return wrap(resolveDelegate().createSocket(address, port, localAddress, localPort), address.getHostName());
    }

    private record ZoneLdapTrust(List<String> caCertificates, boolean skipSslValidation) {
    }
}
