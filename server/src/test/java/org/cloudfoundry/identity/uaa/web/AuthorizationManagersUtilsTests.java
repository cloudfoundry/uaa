package org.cloudfoundry.identity.uaa.web;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationManagersUtilsTests {

    @Nested
    class AnonymousOrFullyAuthenticated {
        private final AuthorizationManager<Object> matcher = AuthorizationManagersUtils.anonymousOrFullyAuthenticated();

        @Test
        void anonymous() {
            var authentication = new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"));

            assertThat(matcher.check(() -> authentication, null).isGranted()).isTrue();
        }

        @Test
        void fullyAuthenticated() {
            var authentication = UsernamePasswordAuthenticationToken.authenticated("ignored", null, AuthorityUtils.NO_AUTHORITIES);

            assertThat(matcher.check(() -> authentication, null).isGranted()).isTrue();
        }

        @Test
        void rememberMeAuthentication() {
            var authentication = new RememberMeAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"));

            assertThat(matcher.check(() -> authentication, null).isGranted()).isFalse();
        }
    }
}
