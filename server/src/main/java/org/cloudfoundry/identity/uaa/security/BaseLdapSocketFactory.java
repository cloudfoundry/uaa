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
     * TLS endpoint identification algorithm for sockets from this factory, or {@code null} to
     * disable hostname verification (as {@link SkipSslLdapSocketFactory} does).
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
     * Ensures the target hostname is attached before the handshake; see {@link HostnameAwareSslSocket}.
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
        return wrap(delegate.createSocket(inetAddress, i), HostnameAwareSslSocket.targetHost(inetAddress));
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
        return wrap(delegate.createSocket(inetAddress, i, inetAddress1, i1), HostnameAwareSslSocket.targetHost(inetAddress));
    }
}
