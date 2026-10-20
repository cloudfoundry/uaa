/*
 *********************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.security;

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
import java.util.regex.Pattern;

/**
 * Delegating {@link SSLSocket} that guarantees a target hostname is attached
 * to the socket (via SNI / endpoint identification algorithm) before a TLS
 * handshake begins.
 * <p>
 * This matters specifically for sockets created via the no-arg
 * {@link javax.net.SocketFactory#createSocket()} method, which JNDI's LDAP
 * provider uses instead of {@code createSocket(host, port)} whenever
 * {@code com.sun.jndi.ldap.connect.timeout} is configured (see
 * {@code com.sun.jndi.ldap.Connection}): it creates an unconnected socket and
 * later calls {@code connect(SocketAddress, int)} directly, so the hostname
 * is only available at {@code connect} time, not at {@code createSocket}
 * time.
 * <p>
 * Some JSSE providers (observed with Bouncy Castle FIPS, {@code bctls-fips})
 * do not infer the peer hostname from a later plain
 * {@code connect(SocketAddress)} call the way the default Sun JSSE provider
 * does, and fail the handshake with
 * {@code CertificateException: No hostname specified for HTTPS endpoint ID check}.
 * Capturing the hostname at {@code connect} time and explicitly attaching it
 * via {@link SSLParameters} closes that gap for every JSSE provider.
 */
class HostnameAwareSslSocket extends SSLSocket {

    private final SSLSocket delegate;
    private final String endpointIdentificationAlgorithm;
    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private boolean hostnameApplied;

    /**
     * @param delegate                        the real SSL socket to delegate all behavior to
     * @param endpointIdentificationAlgorithm the algorithm to request (e.g. {@code "LDAPS"}),
     *                                         or {@code null} to explicitly disable endpoint identification
     * @param knownHost                        the target hostname if already known at construction time
     *                                         (e.g. for the {@code createSocket(String, int)} overloads), or
     *                                         {@code null} if it will only be known once {@code connect(...)}
     *                                         is called (the no-arg {@code createSocket()} case)
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

    private void applyHostname(String host) {
        hostnameApplied = true;
        SSLParameters params = delegate.getSSLParameters();
        params.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        if (endpointIdentificationAlgorithm != null && host != null && !host.isEmpty() && !IPV4_LITERAL.matcher(host).matches()) {
            try {
                params.setServerNames(List.of(new SNIHostName(host)));
            } catch (IllegalArgumentException _) {
                // host is an IP literal (or otherwise not a valid SNI hostname) -- SNI does not
                // apply; the endpoint identification algorithm above still performs certificate
                // hostname/IP matching using the connected socket's address.
            }
        }
        delegate.setSSLParameters(params);
    }

    // --- SSLSocket-specific methods: delegate ---

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

    // --- Socket methods: delegate ---

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
