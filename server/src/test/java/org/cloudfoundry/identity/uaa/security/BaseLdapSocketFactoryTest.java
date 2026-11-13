package org.cloudfoundry.identity.uaa.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BaseLdapSocketFactoryTest {

    @Mock
    private SSLSocketFactory delegateFactory;
    @Mock
    private SSLSocket sslSocket;

    private SSLParameters params;

    @BeforeEach
    void setUp() {
        params = new SSLParameters();
        lenient().when(sslSocket.getSSLParameters()).thenReturn(params);
    }

    private BaseLdapSocketFactory factory(String algorithm) {
        BaseLdapSocketFactory factory = new BaseLdapSocketFactory() {
            @Override
            protected String getEndpointIdentificationAlgorithm() {
                return algorithm;
            }
        };
        factory.delegate = delegateFactory;
        return factory;
    }

    @Test
    void createSocketWithHostAppliesHostImmediately() throws IOException {
        when(delegateFactory.createSocket("ldap.example.com", 636)).thenReturn(sslSocket);

        Socket socket = factory("LDAPS").createSocket("ldap.example.com", 636);

        assertThat(socket).isInstanceOf(HostnameAwareSslSocket.class);
        assertThat(params.getEndpointIdentificationAlgorithm()).isEqualTo("LDAPS");
        assertThat(params.getServerNames()).containsExactly(new SNIHostName("ldap.example.com"));
    }

    @Test
    void createSocketWithAddressOnlyInetAddressDoesNotSendSni() throws IOException {
        InetAddress address = InetAddress.getByAddress(new byte[]{10, 1, 2, 3});
        when(delegateFactory.createSocket(address, 636)).thenReturn(sslSocket);

        factory("LDAPS").createSocket(address, 636);

        assertThat(params.getEndpointIdentificationAlgorithm()).isEqualTo("LDAPS");
        assertThat(params.getServerNames()).isNull();
    }

    @Test
    void nullAlgorithmIsPropagatedToSocket() throws IOException {
        params.setEndpointIdentificationAlgorithm("HTTPS");
        when(delegateFactory.createSocket("ldap.example.com", 636)).thenReturn(sslSocket);

        factory(null).createSocket("ldap.example.com", 636);

        assertThat(params.getEndpointIdentificationAlgorithm()).isNull();
    }
}