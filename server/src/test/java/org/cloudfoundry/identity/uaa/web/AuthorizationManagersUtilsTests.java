package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.test.ModelTestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.Collections;
import java.util.Set;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtilsTests.TestAuthManager.granted;
import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtilsTests.TestAuthManager.notGranted;
import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtilsTests.TestAuthManager.unknown;

class AuthorizationManagersUtilsTests {

    private final Authentication ANONYMOUS = new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final Authentication NOT_AUTHENTICATED = new TestingAuthenticationToken("test", null);
    private final Authentication FULLY_AUTHENTICATED = new TestingAuthenticationToken("test", null, AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final Authentication REMEMBER_ME = new RememberMeAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

    @AfterAll
    static void afterAll() {
        IdentityZoneHolder.clear();
    }

    @Test
    void noAuthenticationManager() {
        AuthorizationManager<RequestAuthorizationContext> authManager = AuthorizationManagersUtils.anyOf();

        var authorizationDecision = authManager.check(() -> FULLY_AUTHENTICATED, null);

        assertThat(authorizationDecision.isGranted()).isFalse();
    }

    @Test
    void oneAuthenticationManager() {
        var granted = granted();
        var notGranted = notGranted();
        var unknown = unknown();
        assertThat(AuthorizationManagersUtils.anyOf().or(granted).check(() -> FULLY_AUTHENTICATED, null).isGranted()).isTrue();
        assertThat(granted.called).isTrue();
        assertThat(AuthorizationManagersUtils.anyOf().or(notGranted).check(() -> FULLY_AUTHENTICATED, null).isGranted()).isFalse();
        assertThat(notGranted.called).isTrue();
        assertThat(AuthorizationManagersUtils.anyOf().or(unknown).check(() -> FULLY_AUTHENTICATED, null).isGranted()).isFalse();
        assertThat(unknown.called).isTrue();
    }

    @Test
    void manyAuthenticationManagers() {
        var granted = granted();
        var notGranted = notGranted();
        var unknown = unknown();
        var authorizationManager = AuthorizationManagersUtils.anyOf()
                .or(notGranted)
                .or(granted)
                .or(unknown);

        assertThat(authorizationManager.check(() -> FULLY_AUTHENTICATED, null).isGranted()).isTrue();
        assertThat(notGranted.called).isTrue();
        assertThat(granted.called).isTrue();
        assertThat(unknown.called).isFalse();
    }

    @Test
    void anonymous() {
        AuthorizationManager<RequestAuthorizationContext> authManager = AuthorizationManagersUtils.anyOf()
                .anonymous();

        assertThat(authManager.check(() -> ANONYMOUS, null).isGranted()).isTrue();
        assertThat(authManager.check(() -> NOT_AUTHENTICATED, null).isGranted()).isFalse();
        assertThat(authManager.check(() -> FULLY_AUTHENTICATED, null).isGranted()).isFalse();
        assertThat(authManager.check(() -> REMEMBER_ME, null).isGranted()).isFalse();
    }

    @Test
    void fullyAuthenticated() {
        AuthorizationManager<RequestAuthorizationContext> authManager = AuthorizationManagersUtils.anyOf()
                .fullyAuthenticated();

        assertThat(authManager.check(() -> ANONYMOUS, null).isGranted()).isFalse();
        assertThat(authManager.check(() -> NOT_AUTHENTICATED, null).isGranted()).isFalse();
        assertThat(authManager.check(() -> FULLY_AUTHENTICATED, null).isGranted()).isTrue();
        assertThat(authManager.check(() -> REMEMBER_ME, null).isGranted()).isFalse();
    }

    @Test
    void uaaAdmin() {
        AuthorizationManager<RequestAuthorizationContext> authManager = AuthorizationManagersUtils.anyOf().isUaaAdmin();

        assertThat(authManager.check(() -> withScopes("foo.bar"), null).isGranted()).isFalse();
        assertThat(authManager.check(() -> withScopes("uaa.admin"), null).isGranted()).isTrue();
    }

    @Test
    void hasScope() {
        AuthorizationManager<RequestAuthorizationContext> authManager = AuthorizationManagersUtils.anyOf().hasScope("foo.bar");

        assertThat(authManager.check(() -> withScopes("uaa.admin"), null).isGranted()).isFalse();
        assertThat(authManager.check(() -> withScopes("uaa.admin", "foo.bar"), null).isGranted()).isTrue();
    }

    @Test
    void throwOnError() {
        AuthorizationManager<RequestAuthorizationContext> authManager = AuthorizationManagersUtils.anyOf(true).hasScope("foo.bar");

        assertThatThrownBy(
                () -> {authManager.check(() -> withScopes("uaa.admin"), null);}
        ).getCause().isInstanceOf(InsufficientScopeException.class);

    }

    @Test
    void zoneAdmin() {
        AuthorizationManager<RequestAuthorizationContext> authManager = AuthorizationManagersUtils.anyOf().isZoneAdmin();

        IdentityZoneHolder.set(ModelTestUtils.identityZone("someZoneId", "some-domain"));

        assertThat(authManager.check(() -> withScopes("foo.bar"), null).isGranted()).isFalse();
        assertThat(authManager.check(() -> withScopes("zones.someZoneId.admin"), null).isGranted()).isTrue();
    }

    static class TestAuthManager implements AuthorizationManager<RequestAuthorizationContext> {

        public boolean called = false;
        private final AuthorizationDecision authorizationDecision;

        public TestAuthManager(Boolean decision) {
            if (decision == null) {
                this.authorizationDecision = null;
            } else {
                this.authorizationDecision = new AuthorizationDecision(decision);
            }
        }

        public static TestAuthManager granted() {
            return new TestAuthManager(true);
        }

        public static TestAuthManager notGranted() {
            return new TestAuthManager(false);
        }

        public static TestAuthManager unknown() {
            return new TestAuthManager(null);
        }

        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
            called = true;
            return authorizationDecision;
        }
    }

    private Authentication withScopes(String... scopes) {
        return new UaaOauth2Authentication(
                "~ignored~",
                IdentityZone.getUaaZoneId(),
                new OAuth2Request(
                        Collections.emptyMap(),
                        null,
                        Collections.emptySet(),
                        true,
                        Set.of(scopes),
                        Collections.emptySet(),
                        null,
                        Collections.emptySet(),
                        Collections.emptyMap()
                ),
                FULLY_AUTHENTICATED
        );
    }

}
