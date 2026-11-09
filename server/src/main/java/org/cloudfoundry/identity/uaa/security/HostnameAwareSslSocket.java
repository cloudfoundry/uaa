package org.cloudfoundry.identity.uaa.security;

import org.bouncycastle.jsse.BCSSLSocket;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.util.List;
import java.util.function.BiFunction;
import java.util.regex.Pattern;

/**
 * Delegating {@link SSLSocket} that attaches the target hostname (peer host, SNI and endpoint
 * identification algorithm) before the TLS handshake. Needed because JNDI's LDAP provider, when
 * {@code com.sun.jndi.ldap.connect.timeout} is set, uses the no-arg {@code createSocket()} and only
 * supplies the host later via {@code connect(SocketAddress, int)}; Bouncy Castle FIPS JSSE does not
 * infer the host from that call and fails with "No hostname specified for HTTPS endpoint ID check".
 */
class HostnameAwareSslSocket extends SSLSocket {

    private final SSLSocket delegate;
    private final String endpointIdentificationAlgorithm;
    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private boolean hostnameApplied;

    /**
     * @param endpointIdentificationAlgorithm e.g. {@code "LDAPS"}, or {@code null} to disable endpoint identification
     * @param knownHost                       the target host if known now, or {@code null} to take it from {@code connect(...)}
     */
    HostnameAwareSslSocket(SSLSocket delegate, String endpointIdentificationAlgorithm, String knownHost) {
        this.delegate = delegate;
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm;
        if (knownHost != null) {
            applyHostname(knownHost);
        }
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        applyHostnameFromEndpoint(endpoint);
        delegate.connect(endpoint);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        applyHostnameFromEndpoint(endpoint);
        delegate.connect(endpoint, timeout);
    }

    private void applyHostnameFromEndpoint(SocketAddress endpoint) {
        if (!hostnameApplied && endpoint instanceof InetSocketAddress inetSocketAddress) {
            applyHostname(inetSocketAddress.getHostString());
        }
    }

    /**
     * The hostname the address was created with, else its IP literal. Unlike
     * {@link InetAddress#getHostName()}, never does a reverse DNS lookup.
     */
    static String targetHost(InetAddress address) {
        String text = address.toString();
        int slash = text.lastIndexOf('/');
        String hostname = slash > 0 ? text.substring(0, slash) : "";
        return hostname.isEmpty() ? address.getHostAddress() : hostname;
    }

    private void applyHostname(String host) {
        hostnameApplied = true;
        if (delegate instanceof BCSSLSocket bcSocket && host != null && !host.isEmpty()) {
            // BCJSSE checks the endpoint against the peer host (not SNI) and doesn't take it from connect()
            bcSocket.setHost(host);
        }
        SSLParameters params = delegate.getSSLParameters();
        params.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        if (endpointIdentificationAlgorithm != null && host != null && !host.isEmpty() && !IPV4_LITERAL.matcher(host).matches()) {
            try {
                params.setServerNames(List.of(new SNIHostName(host)));
            } catch (IllegalArgumentException _) {
                // not a valid SNI hostname (e.g. IPv6 literal); endpoint identification still applies
            }
        }
        delegate.setSSLParameters(params);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        delegate.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        delegate.setEnabledProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return delegate.getSession();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return delegate.getHandshakeSession();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.addHandshakeCompletedListener(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.removeHandshakeCompletedListener(listener);
    }

    @Override
    public void startHandshake() throws IOException {
        delegate.startHandshake();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        delegate.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        delegate.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        delegate.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        delegate.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return delegate.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        delegate.setSSLParameters(params);
    }

    @Override
    public String getApplicationProtocol() {
        return delegate.getApplicationProtocol();
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return delegate.getHandshakeApplicationProtocol();
    }

    @Override
    public void setHandshakeApplicationProtocolSelector(BiFunction<SSLSocket, List<String>, String> selector) {
        delegate.setHandshakeApplicationProtocolSelector(selector);
    }

    @Override
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return delegate.getHandshakeApplicationProtocolSelector();
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        delegate.bind(bindpoint);
    }

    @Override
    public InetAddress getInetAddress() {
        return delegate.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return delegate.getLocalAddress();
    }

    @Override
    public int getPort() {
        return delegate.getPort();
    }

    @Override
    public int getLocalPort() {
        return delegate.getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return delegate.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return delegate.getLocalSocketAddress();
    }

    @Override
    public SocketChannel getChannel() {
        return delegate.getChannel();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return delegate.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return delegate.getOutputStream();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        delegate.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return delegate.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        delegate.setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return delegate.getSoLinger();
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        delegate.sendUrgentData(data);
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        delegate.setOOBInline(on);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return delegate.getOOBInline();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        delegate.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return delegate.getSoTimeout();
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException {
        delegate.setSendBufferSize(size);
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return delegate.getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        delegate.setReceiveBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return delegate.getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        delegate.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return delegate.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        delegate.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return delegate.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        delegate.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return delegate.getReuseAddress();
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public void shutdownInput() throws IOException {
        delegate.shutdownInput();
    }

    @Override
    public void shutdownOutput() throws IOException {
        delegate.shutdownOutput();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    @Override
    public boolean isConnected() {
        return delegate.isConnected();
    }

    @Override
    public boolean isBound() {
        return delegate.isBound();
    }

    @Override
    public boolean isClosed() {
        return delegate.isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        return delegate.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return delegate.isOutputShutdown();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
    }
}
