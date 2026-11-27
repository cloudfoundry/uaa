package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.UaaProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AdminTokenNetworkPolicyTests {
    private final AdminTokenNetworkPolicy policy = policy(true, List.of("192.0.2.0/24", "2001:db8::/32"));

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @ParameterizedTest
    @ValueSource(strings = {"uaa.admin", "cloud_controller.admin", "cloud_controller.admin_read_only",
            "cloud_controller.global_auditor", "zones.tenant.admin", "zones.*.admin"})
    void protectsScopesAndAuthorities(String scope) {
        request("198.51.100.1");
        assertThatThrownBy(() -> policy.checkIssuance(List.of(scope), List.of())).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> policy.checkIssuance(List.of("openid"), List.of(scope))).isInstanceOf(AccessDeniedException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"192.0.2.0", "192.0.2.255", "2001:db8::1", "::ffff:192.0.2.10"})
    void acceptsAllowedNumericAddresses(String address) {
        request(address);
        assertThatCode(() -> policy.checkIssuance(List.of("uaa.admin"), List.of())).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"192.0.3.0", "2001:db9::1", "localhost", "127.1", "192.0.2.1/32",
            "[2001:db8::1]", "2001:db8::1%eth0", "", "192.0.2.1,198.51.100.1"})
    void rejectsOutsideOrMalformedAddresses(String address) {
        request(address);
        assertThatThrownBy(() -> policy.checkIssuance(List.of("uaa.admin"), List.of())).isInstanceOf(AccessDeniedException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "127.1", "192.0.2.1/33", "2001:db8::/129", "192.0.2.1/",
            "192.0.2.1/-1", "192.0.2.1/255.255.255.0", "192.0.2.1/24/1", " 192.0.2.1",
            "::ffff:192.0.2.1/120", "[2001:db8::1]", "fe80::1%lo0", ""})
    void rejectsInvalidConfigurationEvenWhenDisabled(String cidr) {
        assertThatThrownBy(() -> policy(false, List.of(cidr))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void missingRequestFailsClosedOnlyForProtectedTokens() {
        assertThatThrownBy(() -> policy.checkIssuance(List.of("uaa.admin"), List.of())).isInstanceOf(AccessDeniedException.class);
        assertThatCode(() -> policy.checkIssuance(List.of("openid", "zones.read", "not.uaa.admin"), List.of())).doesNotThrowAnyException();
        assertThatCode(() -> policy(false, List.of()).checkIssuance(List.of("uaa.admin"), List.of())).doesNotThrowAnyException();
    }

    @Test
    void enabledEmptyAllowlistDeniesAllProtectedTokens() {
        request("192.0.2.1");
        assertThatThrownBy(() -> policy(true, List.of()).checkIssuance(List.of("uaa.admin"), List.of()))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void ignoresSpoofedHeadersAndProtectsRetainedRefreshScopes() {
        MockHttpServletRequest request = request("198.51.100.1");
        request.addHeader("X-Forwarded-For", "192.0.2.1");
        request.addHeader("X-Real-IP", "192.0.2.1");
        assertThatThrownBy(() -> policy.checkClaims(Map.of("scope", List.of("openid"),
                "granted_scopes", List.of("uaa.admin", "openid")))).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> policy.checkClaims(Map.of("scope", List.of("openid"),
                "authorities", "uaa.admin,openid"))).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void supportsExactAdditionalProtectedScopes() {
        AdminTokenNetworkPolicy additional = new AdminTokenNetworkPolicy(new UaaProperties.AdminTokenNetworkPolicy(
                true, List.of(), List.of("clients.write")));
        assertThatThrownBy(() -> additional.checkIssuance(List.of("clients.write"), List.of())).isInstanceOf(AccessDeniedException.class);
    }

    private static AdminTokenNetworkPolicy policy(boolean enabled, List<String> cidrs) {
        return new AdminTokenNetworkPolicy(new UaaProperties.AdminTokenNetworkPolicy(enabled, cidrs, List.of()));
    }

    private static MockHttpServletRequest request(String address) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(address);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return request;
    }
}
