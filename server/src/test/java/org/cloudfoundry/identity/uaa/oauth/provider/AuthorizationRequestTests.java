package org.cloudfoundry.identity.uaa.oauth.provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationRequestTests {

    private AuthorizationRequest authorizationRequest;
    private AuthorizationRequest authorizationRequest2;

    @BeforeEach
    void setUp() throws Exception {
        authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setAuthorities(Collections.emptyList());
        authorizationRequest2 = new AuthorizationRequest(Map.of("client_id", "id"), "id", Set.of("scope"), Set.of("resourceIds"),
                AuthorityUtils.createAuthorityList("scope", "authorities"), true, "state", "redirect:uri", Set.of("code"));
    }

    @Test
    void testHashCode() {
        assertThat(authorizationRequest)
                .hasSameHashCodeAs(authorizationRequest)
                .doesNotHaveSameHashCodeAs(authorizationRequest2);
    }

    @Test
    void equals() {
        assertThat(authorizationRequest)
                .isEqualTo(authorizationRequest)
                .isNotEqualTo(authorizationRequest2);
        assertThat(new AuthorizationRequest(Map.of("client_id", "id"), "id", Set.of("scope"), Set.of("resourceIds"),
                AuthorityUtils.createAuthorityList("scope", "authorities"), false, "xxx", "redirect:uri", Set.of("code")))
                .isNotEqualTo(authorizationRequest2);
    }
}
