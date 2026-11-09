package org.cloudfoundry.identity.uaa.security;

import org.bouncycastle.jsse.BCSSLSocket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.function.BiFunction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@ExtendWith(MockitoExtension.class)
class HostnameAwareSslSocketTest {

    @Mock
    private SSLSocket delegate;

    private SSLParameters params;

    @BeforeEach
    void setUp() {
        params = new SSLParameters();
        lenient().when(delegate.getSSLParameters()).thenReturn(params);
    }

    @Test
    void knownHostIsAppliedAtConstruction() {
        new HostnameAwareSslSocket(delegate, "LDAPS", "ldap.example.com");

        verify(delegate).setSSLParameters(params);
        assertThat(params.getEndpointIdentificationAlgorithm()).isEqualTo("LDAPS");
        assertThat(params.getServerNames()).containsExactly(new SNIHostName("ldap.example.com"));
    }

    @Test
    void unknownHostIsNotAppliedAtConstruction() {
        new HostnameAwareSslSocket(delegate, "LDAPS", null);

        verify(delegate, never()).setSSLParameters(any());
    }

    @Test
    void connectAppliesHostnameFromEndpoint() throws IOException {
        HostnameAwareSslSocket socket = new HostnameAwareSslSocket(delegate, "LDAPS", null);
        SocketAddress endpoint = InetSocketAddress.createUnresolved("ldap.example.com", 636);

        socket.connect(endpoint);

        verify(delegate).setSSLParameters(params);
        verify(delegate).connect(endpoint);
        assertThat(params.getEndpointIdentificationAlgorithm()).isEqualTo("LDAPS");
        assertThat(params.getServerNames()).containsExactly(new SNIHostName("ldap.example.com"));
    }

    @Test
    void connectWithTimeoutAppliesHostnameFromEndpoint() throws IOException {
        HostnameAwareSslSocket socket = new HostnameAwareSslSocket(delegate, "LDAPS", null);
        SocketAddress endpoint = InetSocketAddress.createUnresolved("ldap.example.com", 636);

        socket.connect(endpoint, 1000);

        verify(delegate).setSSLParameters(params);
        verify(delegate).connect(endpoint, 1000);
        assertThat(params.getServerNames()).containsExactly(new SNIHostName("ldap.example.com"));
    }

    @Test
    void connectDoesNotOverrideAlreadyKnownHost() throws IOException {
        HostnameAwareSslSocket socket = new HostnameAwareSslSocket(delegate, "LDAPS", "known.example.com");
        SocketAddress endpoint = InetSocketAddress.createUnresolved("other.example.com", 636);

        socket.connect(endpoint);

        verify(delegate).setSSLParameters(params);
        verify(delegate).connect(endpoint);
        assertThat(params.getServerNames()).containsExactly(new SNIHostName("known.example.com"));
    }

    @Test
    void connectIgnoresNonInetSocketAddress() throws IOException {
        HostnameAwareSslSocket socket = new HostnameAwareSslSocket(delegate, "LDAPS", null);
        SocketAddress endpoint = new SocketAddress() {
        };

        socket.connect(endpoint);

        verify(delegate, never()).setSSLParameters(any());
        verify(delegate).connect(endpoint);
    }

    @Test
    void nullAlgorithmDisablesEndpointIdentificationAndSni() {
        params.setEndpointIdentificationAlgorithm("HTTPS");

        new HostnameAwareSslSocket(delegate, null, "ldap.example.com");

        assertThat(params.getEndpointIdentificationAlgorithm()).isNull();
        assertThat(params.getServerNames()).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.1.2.3", "::1", "bad_host!"})
    @EmptySource
    void invalidSniHostsStillSetEndpointIdentification(String host) {
        new HostnameAwareSslSocket(delegate, "LDAPS", host);

        verify(delegate).setSSLParameters(params);
        assertThat(params.getEndpointIdentificationAlgorithm()).isEqualTo("LDAPS");
        assertThat(params.getServerNames()).isNull();
    }

    @Test
    void sslMethodsAreDelegated() {
        HostnameAwareSslSocket socket = new HostnameAwareSslSocket(delegate, "LDAPS", null);
        when(delegate.getEnabledProtocols()).thenReturn(new String[]{"TLSv1.3"});
        when(delegate.isConnected()).thenReturn(true);

        assertThat(socket.getEnabledProtocols()).containsExactly("TLSv1.3");
        assertThat(socket.isConnected()).isTrue();
        socket.setUseClientMode(true);
        verify(delegate).setUseClientMode(true);
    }

    @Test
    void bcJsseSocketReceivesPeerHostOnConnect() throws IOException {
        SSLSocket bcDelegate = mock(SSLSocket.class, withSettings().extraInterfaces(BCSSLSocket.class));
        when(bcDelegate.getSSLParameters()).thenReturn(params);
        HostnameAwareSslSocket socket = new HostnameAwareSslSocket(bcDelegate, "LDAPS", null);

        socket.connect(InetSocketAddress.createUnresolved("ldap.example.com", 636), 1000);

        verify((BCSSLSocket) bcDelegate).setHost("ldap.example.com");
    }

    @Test
    void alpnMethodsAreDelegated() {
        HostnameAwareSslSocket socket = new HostnameAwareSslSocket(delegate, "LDAPS", null);
        BiFunction<SSLSocket, List<String>, String> selector = (s, protocols) -> protocols.getFirst();
        when(delegate.getApplicationProtocol()).thenReturn("ldap");
        when(delegate.getHandshakeApplicationProtocol()).thenReturn("ldap-hs");
        when(delegate.getHandshakeApplicationProtocolSelector()).thenReturn(selector);

        socket.setHandshakeApplicationProtocolSelector(selector);

        verify(delegate).setHandshakeApplicationProtocolSelector(selector);
        assertThat(socket.getApplicationProtocol()).isEqualTo("ldap");
        assertThat(socket.getHandshakeApplicationProtocol()).isEqualTo("ldap-hs");
        assertThat(socket.getHandshakeApplicationProtocolSelector()).isSameAs(selector);
    }

    @Test
    void targetHostReturnsSuppliedHostName() throws UnknownHostException {
        InetAddress address = InetAddress.getByAddress("ldap.example.com", new byte[]{10, 1, 2, 3});

        assertThat(HostnameAwareSslSocket.targetHost(address)).isEqualTo("ldap.example.com");
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.1.2.3", "::1"})
    void targetHostReturnsLiteralForAddressOnlyInetAddress(String literal) throws UnknownHostException {
        InetAddress address = InetAddress.getByAddress(InetAddress.getByName(literal).getAddress());

        assertThat(HostnameAwareSslSocket.targetHost(address)).isEqualTo(address.getHostAddress());
    }
}
