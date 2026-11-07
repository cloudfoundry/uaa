package org.cloudfoundry.identity.uaa.security;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public abstract class BaseLdapSocketFactory extends SSLSocketFactory {
    private static SocketFactory instance;
    protected SSLSocketFactory delegate;

    public static SocketFactory getDefault() {
        if (instance == null) {
            instance = new LdapSocketFactory();
        }

        return instance;
    }

    /**
     * The TLS endpoint identification algorithm to request for sockets created by this
     * factory, or {@code null} to explicitly disable endpoint identification (hostname
     * verification). Defaults to {@code "LDAPS"}, the algorithm the JDK itself uses for
     * direct {@code ldaps://} connections. Subclasses that intentionally skip certificate/
     * hostname verification (e.g. {@link SkipSslLdapSocketFactory}) should override this to
     * return {@code null}.
     */
    protected String getEndpointIdentificationAlgorithm() {
        return "LDAPS";
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    /**
     * Wraps a freshly created socket so that a target hostname is always attached before a
     * TLS handshake starts. This matters most for the no-arg {@link #createSocket()}
     * overload, used by JNDI's LDAP provider instead of {@code createSocket(host, port)}
     * whenever {@code com.sun.jndi.ldap.connect.timeout} is configured (see
     * {@link LdapSocketFactory}/{@code LdapIntegrationConfig}): JNDI creates an unconnected
     * socket and only supplies the hostname later via {@code connect(SocketAddress, int)}.
     * Some JSSE providers (observed with Bouncy Castle FIPS) do not infer the hostname from
     * that later {@code connect} call, causing handshake failures such as
     * "No hostname specified for HTTPS endpoint ID check".
     */
    private Socket wrap(Socket socket, String knownHost) {
        return new HostnameAwareSslSocket((SSLSocket) socket, getEndpointIdentificationAlgorithm(), knownHost);
    }

    @Override
    public Socket createSocket() throws IOException {
        return wrap(delegate.createSocket(), null);
    }

    @Override
    public Socket createSocket(Socket socket, String s, int i, boolean b) throws IOException {
        return wrap(delegate.createSocket(socket, s, i, b), s);
    }

    @Override
    public Socket createSocket(String s, int i) throws IOException {
        return wrap(delegate.createSocket(s, i), s);
    }

    @Override
    public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException {
        return wrap(delegate.createSocket(s, i, inetAddress, i1), s);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return wrap(delegate.createSocket(inetAddress, i), inetAddress.getHostName());
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
        return wrap(delegate.createSocket(inetAddress, i, inetAddress1, i1), inetAddress.getHostName());
    }
}
