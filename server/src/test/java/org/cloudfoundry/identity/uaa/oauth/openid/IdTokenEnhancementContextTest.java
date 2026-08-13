package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class IdTokenEnhancementContextTest {

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put((String) kv[i], kv[i + 1]);
        }
        return map;
    }

    private IdTokenEnhancementContext context(Map<String, Object> baseClaims, boolean allowModification) {
        return new IdTokenEnhancementContext(
                baseClaims,
                mock(OAuth2Authentication.class),
                mapOf("scope", "openid"),
                mapOf("jti", "refresh-jti"),
                mapOf("acme.tenant", "blue"),
                allowModification);
    }

    @Test
    void setClaim_addsNewClaim() {
        IdTokenEnhancementContext context = context(mapOf("sub", "marissa"), false);

        boolean applied = context.setClaim("tenant", "blue");

        assertThat(applied).isTrue();
        assertThat(context.getClaims())
                .containsEntry("tenant", "blue")
                .containsEntry("sub", "marissa");
        assertThat(context.getRejectedClaimModifications()).isEmpty();
    }

    @Test
    void getClaims_returnsSnapshotThatDoesNotLeakInternalState() {
        IdTokenEnhancementContext context = context(mapOf("sub", "marissa"), false);

        context.getClaims().put("injected", "nope");

        assertThat(context.getClaims()).doesNotContainKey("injected");
    }

    @Test
    void exposesAuthenticationAccessRefreshAndProperties() {
        OAuth2Authentication authentication = mock(OAuth2Authentication.class);
        IdTokenEnhancementContext context = new IdTokenEnhancementContext(
                mapOf("sub", "marissa"),
                authentication,
                mapOf("scope", "openid", "client_id", "login"),
                mapOf("jti", "refresh-jti"),
                mapOf("acme.tenant", "blue"),
                false);

        assertThat(context.getAuthentication()).isSameAs(authentication);
        assertThat(context.getAccessTokenClaim("scope")).isEqualTo("openid");
        assertThat(context.getRefreshTokenClaim("jti")).isEqualTo("refresh-jti");
        assertThat(context.getProperty("acme.tenant")).isEqualTo("blue");
        assertThat(context.isClaimModificationAllowed()).isFalse();
    }

    @Test
    void hasClaim_reflectsBaseAndAddedClaims() {
        IdTokenEnhancementContext context = context(mapOf("sub", "marissa"), false);

        assertThat(context.hasClaim("sub")).isTrue();
        assertThat(context.hasClaim("tenant")).isFalse();
        context.setClaim("tenant", "blue");
        assertThat(context.hasClaim("tenant")).isTrue();
    }

    @Nested
    class WhenClaimModificationDisallowed {

        @Test
        void setClaim_existingClaim_isRejectedAndOriginalPreserved() {
            IdTokenEnhancementContext context =
                    context(mapOf("sub", "marissa", "email", "marissa@test.org"), false);

            boolean applied = context.setClaim("email", "attacker@evil.example");

            assertThat(applied).isFalse();
            assertThat(context.getClaim("email")).isEqualTo("marissa@test.org");
            assertThat(context.getRejectedClaimModifications()).containsExactly("email");
            assertThat(context.getModifiedClaims()).isEmpty();
        }

        @Test
        void setClaim_newClaimIsStillAllowed() {
            IdTokenEnhancementContext context = context(mapOf("sub", "marissa"), false);

            assertThat(context.setClaim("tenant", "blue")).isTrue();
            assertThat(context.getClaim("tenant")).isEqualTo("blue");
        }
    }

    @Nested
    class WhenClaimModificationAllowed {

        @Test
        void setClaim_existingClaim_isOverwrittenAndRecorded() {
            IdTokenEnhancementContext context =
                    context(mapOf("sub", "marissa", "email", "marissa@test.org"), true);

            boolean applied = context.setClaim("email", "marissa@corp.example");

            assertThat(applied).isTrue();
            assertThat(context.getClaim("email")).isEqualTo("marissa@corp.example");
            assertThat(context.getModifiedClaims()).containsExactly("email");
            assertThat(context.getRejectedClaimModifications()).isEmpty();
        }
    }
}
