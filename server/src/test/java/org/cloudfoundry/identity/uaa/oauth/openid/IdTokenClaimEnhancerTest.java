package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdTokenClaimEnhancerTest {

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put((String) kv[i], kv[i + 1]);
        }
        return map;
    }

    private final OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    private final Map<String, Object> accessTokenClaims =
            mapOf("scope", List.of("openid", "roles"), "client_id", "login");
    private final Map<String, Object> refreshTokenClaims = mapOf("jti", "refresh-jti");

    private Map<String, Object> enhance(IdTokenClaimEnhancer enhancer, Map<String, Object> idTokenClaims) {
        return enhancer.enhance(idTokenClaims, authentication, accessTokenClaims, refreshTokenClaims);
    }

    @Test
    void enhance_withNoEnhancers_returnsClaimsUnchanged() {
        IdTokenClaimEnhancer enhancer = new IdTokenClaimEnhancer(emptyList(), false);
        Map<String, Object> base = mapOf("sub", "marissa");

        assertThat(enhance(enhancer, base)).isSameAs(base);
    }

    @Test
    void noOp_returnsClaimsUnchanged() {
        Map<String, Object> base = mapOf("sub", "marissa");

        assertThat(enhance(IdTokenClaimEnhancer.noOp(), base)).isSameAs(base);
        assertThat(IdTokenClaimEnhancer.noOp().isClaimModificationAllowed()).isFalse();
    }

    @Test
    void enhance_addsNewRootClaim() {
        IdTokenEnhancer adder = context -> context.setClaim("tenant", "blue");
        IdTokenClaimEnhancer enhancer = new IdTokenClaimEnhancer(List.of(adder), false);

        assertThat(enhance(enhancer, mapOf("sub", "marissa")))
                .containsEntry("sub", "marissa")
                .containsEntry("tenant", "blue");
    }

    @Test
    void enhance_runsEnhancersInRegistrationOrder() {
        IdTokenEnhancer first = context -> context.setClaim("chain", "a");
        IdTokenEnhancer second =
                context -> context.setClaim("chain", String.valueOf(context.getClaim("chain")) + "b");
        // 'second' modifies a claim that 'first' added, which requires modification to be enabled
        IdTokenClaimEnhancer enhancer = new IdTokenClaimEnhancer(List.of(first, second), true);

        assertThat(enhance(enhancer, mapOf("sub", "marissa"))).containsEntry("chain", "ab");
    }

    @Test
    void enhance_enhancerReadsAccessRefreshClaimsAndAuthentication() {
        when(authentication.getName()).thenReturn("marissa");
        IdTokenEnhancer reader = context -> {
            context.setClaim("copied_client", context.getAccessTokenClaim("client_id"));
            context.setClaim("refresh_jti", context.getRefreshTokenClaim("jti"));
            context.setClaim("who", context.getAuthentication().getName());
        };
        IdTokenClaimEnhancer enhancer = new IdTokenClaimEnhancer(List.of(reader), false);

        assertThat(enhance(enhancer, mapOf("sub", "marissa")))
                .containsEntry("copied_client", "login")
                .containsEntry("refresh_jti", "refresh-jti")
                .containsEntry("who", "marissa");
    }

    @Test
    void enhance_existingClaimNotModifiedByDefault() {
        IdTokenEnhancer overwriter = context -> context.setClaim("sub", "somebody-else");
        IdTokenClaimEnhancer enhancer = new IdTokenClaimEnhancer(List.of(overwriter), false);

        assertThat(enhance(enhancer, mapOf("sub", "marissa"))).containsEntry("sub", "marissa");
    }

    @Test
    void enhance_existingClaimModifiedWhenAllowed() {
        IdTokenEnhancer overwriter = context -> context.setClaim("sub", "somebody-else");
        IdTokenClaimEnhancer enhancer = new IdTokenClaimEnhancer(List.of(overwriter), true);

        assertThat(enhance(enhancer, mapOf("sub", "marissa"))).containsEntry("sub", "somebody-else");
    }

    @Test
    void enhance_doesNotMutateTheProvidedBaseMap() {
        IdTokenEnhancer adder = context -> context.setClaim("tenant", "blue");
        IdTokenClaimEnhancer enhancer = new IdTokenClaimEnhancer(List.of(adder), false);
        Map<String, Object> base = mapOf("sub", "marissa");

        enhance(enhancer, base);

        assertThat(base).doesNotContainKey("tenant");
    }
}
