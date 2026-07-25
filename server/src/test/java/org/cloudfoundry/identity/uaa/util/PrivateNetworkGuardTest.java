package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PrivateNetworkGuardTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1",        // loopback
            "::1",              // IPv6 loopback
            "10.0.0.1",         // RFC-1918 class A
            "172.16.0.1",       // RFC-1918 class B
            "192.168.1.1",      // RFC-1918 class C
            "169.254.1.1",      // link-local
            "169.254.169.254",  // cloud metadata
            "224.0.0.1",        // multicast
    })
    void blockedAddresses(String ip) throws UnknownHostException {
        assertThat_isBlocked(ip, true);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
    })
    void publicAddressesAreNotBlocked(String ip) throws UnknownHostException {
        assertThat_isBlocked(ip, false);
    }

    @Test
    void assertPublic_rejectsPrivateUri() {
        assertThatThrownBy(() -> PrivateNetworkGuard.assertPublic(URI.create("https://192.168.0.1/jwks")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("blocked");
    }

    @Test
    void assertPublic_rejectsUriWithNoHost() {
        assertThatThrownBy(() -> PrivateNetworkGuard.assertPublic(URI.create("/relative/path")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no host");
    }

    @Test
    void assertPublic_acceptsPublicHost() {
        assertThatNoException().isThrownBy(
                () -> PrivateNetworkGuard.assertPublic(URI.create("https://1.1.1.1/jwks")));
    }

    private static void assertThat_isBlocked(String ip, boolean expected) throws UnknownHostException {
        InetAddress addr = InetAddress.getByName(ip);
        org.assertj.core.api.Assertions.assertThat(PrivateNetworkGuard.isBlocked(addr))
                .as("isBlocked(%s)", ip)
                .isEqualTo(expected);
    }
}
