package org.cloudfoundry.identity.uaa.authentication.manager;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserTestFactory;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class LoginAuthenticationManagerTests {

    private LoginAuthenticationManager manager;
    private UaaUserDatabase userDatabase;
    private TestApplicationEventPublisher<IdentityProviderAuthenticationSuccessEvent> publisher;
    private IdentityZoneManager mockIdentityZoneManager;

    @BeforeEach
    void setUp() {
        publisher = TestApplicationEventPublisher.forEventClass(IdentityProviderAuthenticationSuccessEvent.class);
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        userDatabase = mock(UaaUserDatabase.class);
        manager = new LoginAuthenticationManager(mockIdentityZoneManager, userDatabase);
        manager.setApplicationEventPublisher(publisher);
        OAuth2Authentication oauth2Authentication = new OAuth2Authentication(new AuthorizationRequest("client", Arrays.asList("read",
                "write")).createOAuth2Request(), null);
        SecurityContextImpl context = new SecurityContextImpl();
        context.setAuthentication(oauth2Authentication);
        SecurityContextHolder.setContext(context);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void notProcessingWrongType() {
        Authentication authentication = manager.authenticate(new UsernamePasswordAuthenticationToken("foo", "bar"));
        assertThat(authentication).isNull();
    }

    @Test
    void notProcessingNotAuthenticated() {
        SecurityContextHolder.clearContext();
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertThat(authentication).isNull();
    }

    @Test
    void happyDayNoAutoAdd() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar").modifyOrigin(OriginKeys.LOGIN_SERVER);
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getName()).isEqualTo(user.getUsername());
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getId()).isEqualTo(user.getId());
    }

    @Test
    void happyDayWithAuthorities() {
        UaaUser user = UaaUserTestFactory.getAdminUser("FOO", "foo", "fo@test.org", "Foo", "Bar").modifyOrigin(OriginKeys.LOGIN_SERVER);
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getName()).isEqualTo(user.getUsername());
        assertThat(authentication.getAuthorities()).isEqualTo(user.getAuthorities());
    }

    @Test
    void userNotFoundNoAutoAdd() {
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        assertThatThrownBy(() -> manager.authenticate(UaaAuthenticationTestFactory.getAuthenticationRequest("foo"))).asInstanceOf(InstanceOfAssertFactories.throwable(BadCredentialsException.class));
    }

    @Test
    void happyDayAutoAddButWithExistingUser() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar").modifyOrigin(OriginKeys.LOGIN_SERVER);
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo", true));
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getName()).isEqualTo(user.getUsername());
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getId()).isEqualTo(user.getId());
    }

    @Test
    void unsuccessfulAutoAddButWithNewUser() {
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        assertThatThrownBy(() -> manager.authenticate(UaaAuthenticationTestFactory.getAuthenticationRequest("foo", true))).asInstanceOf(InstanceOfAssertFactories.throwable(BadCredentialsException.class));
    }

    @Test
    void successfulAuthenticationPublishesEvent() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar").modifyOrigin(OriginKeys.LOGIN_SERVER);
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        AuthzAuthenticationRequest authenticationRequest = UaaAuthenticationTestFactory.getAuthenticationRequest("foo");
        manager.authenticate(authenticationRequest);

        assertThat(publisher.getEventCount()).isOne();
        assertThat(publisher.getLatestEvent().getUser().getUsername()).isEqualTo("foo");
    }

    @Test
    void userIdOfAUaaOriginUserIsNotAllowedForExternalLogin() {
        UaaUser user = UaaUserTestFactory.getAdminUser("some-user-id", "admin", "admin@test.org", "Ad", "Min");
        when(userDatabase.retrieveUserById("some-user-id")).thenReturn(user);
        AuthzAuthenticationRequest request = requestFor(Map.of("user_id", "some-user-id"));

        assertThatThrownBy(() -> manager.authenticate(request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("uaa origin not allowed for external login server");
        assertThat(publisher.getEventCount()).isZero();
    }

    @Test
    void userIdOfAUaaOriginUserIsNotAllowedWhenTheRequestNamesAnotherOrigin() {
        UaaUser user = UaaUserTestFactory.getAdminUser("some-user-id", "admin", "admin@test.org", "Ad", "Min");
        when(userDatabase.retrieveUserById("some-user-id")).thenReturn(user);
        AuthzAuthenticationRequest request = requestFor(
                Map.of("user_id", "some-user-id", OriginKeys.ORIGIN, "some-other-origin"));

        assertThatThrownBy(() -> manager.authenticate(request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("uaa origin not allowed for external login server");
        assertThat(publisher.getEventCount()).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {OriginKeys.LOGIN_SERVER, OriginKeys.LDAP, "some-saml-origin"})
    void userIdOfAUserOfAnotherOriginIsAuthenticated(String origin) {
        UaaUser user = new UaaUser("some-user-id", "external", "", "external@test.org", UaaAuthority.USER_AUTHORITIES,
                "Ex", "Ternal", new Date(), new Date(), origin, "externalId", false,
                mockIdentityZoneManager.getCurrentIdentityZoneId(), "some-user-id", new Date());
        when(userDatabase.retrieveUserById("some-user-id")).thenReturn(user);

        Authentication authentication = manager.authenticate(requestFor(Map.of("user_id", "some-user-id")));

        assertThat(((UaaPrincipal) authentication.getPrincipal()).getId()).isEqualTo("some-user-id");
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getOrigin()).isEqualTo(origin);
    }

    private static AuthzAuthenticationRequest requestFor(Map<String, String> info) {
        return new AuthzAuthenticationRequest(info,
                (UaaAuthenticationDetails) UaaAuthenticationTestFactory.getAuthenticationRequest("foo", true).getDetails());
    }

    @ParameterizedTest
    @ValueSource(strings = {"UAA", "Uaa", "uAA"})
    void uaaOriginInAnotherCaseIsNotAllowedForExternalLogin(String origin) {
        AuthzAuthenticationRequest request = requestFor(Map.of("username", "admin", OriginKeys.ORIGIN, origin));

        assertThatThrownBy(() -> manager.authenticate(request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("uaa origin not allowed for external login server");
        verify(userDatabase, never()).retrieveUserByName(anyString(), anyString());
    }

    @Test
    void aUserOfTheUaaOriginFoundForAnotherSpellingOfTheOriginIsNotAllowed() {
        // a database that compares accents and case loosely can match "ua\u00e1" with "uaa"
        UaaUser admin = UaaUserTestFactory.getAdminUser("some-user-id", "admin", "admin@test.org", "Ad", "Min");
        when(userDatabase.retrieveUserByName("admin", "ua\u00e1")).thenReturn(admin);
        AuthzAuthenticationRequest request = requestFor(Map.of("username", "admin", OriginKeys.ORIGIN, "ua\u00e1"));

        assertThatThrownBy(() -> manager.authenticate(request))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("uaa origin not allowed for external login server");
        assertThat(publisher.getEventCount()).isZero();
    }

    @Nested
    class GetUser {
        @Test
        void uaaOriginNotAllowedForExternalLogin() {
            AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest("user", true);
            Map<String, String> info = Map.of(OriginKeys.ORIGIN, OriginKeys.UAA);
            assertThatThrownBy(() -> manager.getUser(req1, info))
                    .isInstanceOf(BadCredentialsException.class)
                    .hasMessage("uaa origin not allowed for external login server");
        }

        @Test
        void byDefault() {
            AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest("user", true);
            HashMap<String, String> info = new HashMap<>();
            info.put("email", "user@example.com");
            info.put("given_name", "Jane");
            info.put("family_name", "Doe");
            info.put(OriginKeys.ORIGIN, "test-origin");
            UaaUser user = manager.getUser(req1, info);

            assertThat(user.getUsername()).isEqualTo("user");
            assertThat(user.getEmail()).isEqualTo("user@example.com");
            assertThat(user.getGivenName()).isEqualTo("Jane");
            assertThat(user.getFamilyName()).isEqualTo("Doe");
            assertThat(user.getPassword()).isEqualTo("");
            assertThat(user.getAuthorities()).isEqualTo(UaaAuthority.USER_AUTHORITIES);
            assertThat(user.getOrigin()).isEqualTo("test-origin");
            assertThat(user.getExternalId()).isEqualTo("user");
            assertThat(user.getZoneId()).isEqualTo(mockIdentityZoneManager.getCurrentIdentityZoneId());
        }

        @Test
        void withoutOrigin() {
            AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest("user", true);
            Map<String, String> info = Map.of("email", "user@example.com");
            UaaUser user = manager.getUser(req1, info);

            assertThat(user.getUsername()).isEqualTo("user");
            assertThat(user.getEmail()).isEqualTo("user@example.com");
            assertThat(user.getPassword()).isEqualTo("");
            assertThat(user.getAuthorities()).isEqualTo(UaaAuthority.USER_AUTHORITIES);
            assertThat(user.getOrigin()).isEqualTo(OriginKeys.LOGIN_SERVER);
            assertThat(user.getExternalId()).isEqualTo("user");
            assertThat(user.getZoneId()).isEqualTo(mockIdentityZoneManager.getCurrentIdentityZoneId());
        }
    }
}
