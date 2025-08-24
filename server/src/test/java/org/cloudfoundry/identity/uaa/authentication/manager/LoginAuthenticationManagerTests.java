package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
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
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.assertj.core.api.HamcrestCondition.matching;
import static org.cloudfoundry.identity.uaa.user.UaaUserMatcher.aUaaUser;
import static org.mockito.Mockito.mock;

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
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getName()).isEqualTo(user.getUsername());
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getId()).isEqualTo(user.getId());
    }

    @Test
    void happyDayWithAuthorities() {
        UaaUser user = UaaUserTestFactory.getAdminUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getName()).isEqualTo(user.getUsername());
        assertThat(authentication.getAuthorities()).isEqualTo(user.getAuthorities());
    }

    @Test
    void userNotFoundNoAutoAdd() {
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> manager.authenticate(UaaAuthenticationTestFactory.getAuthenticationRequest("foo")));
    }

    @Test
    void happyDayAutoAddButWithExistingUser() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo", true));
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getName()).isEqualTo(user.getUsername());
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getId()).isEqualTo(user.getId());
    }

    @Test
    void unsuccessfulAutoAddButWithNewUser() {
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> manager.authenticate(UaaAuthenticationTestFactory.getAuthenticationRequest("foo", true)));
    }

    @Test
    void successfulAuthenticationPublishesEvent() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        AuthzAuthenticationRequest authenticationRequest = UaaAuthenticationTestFactory.getAuthenticationRequest("foo");
        manager.authenticate(authenticationRequest);

        assertThat(publisher.getEventCount()).isOne();
        assertThat(publisher.getLatestEvent().getUser().getUsername()).isEqualTo("foo");
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

            assertThat(user).is(matching(aUaaUser()
                    .withUsername("user")
                    .withEmail("user@example.com")
                    .withGivenName("Jane")
                    .withFamilyName("Doe")
                    .withPassword("")
                    .withAuthorities(Matchers.equalTo(UaaAuthority.USER_AUTHORITIES))
                    .withOrigin("test-origin")
                    .withExternalId("user")
                    .withZoneId(mockIdentityZoneManager.getCurrentIdentityZoneId())));
        }

        @Test
        void withoutOrigin() {
            AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest("user", true);
            Map<String, String> info = Map.of("email", "user@example.com");
            UaaUser user = manager.getUser(req1, info);

            assertThat(user).is(matching(aUaaUser()
                    .withUsername("user")
                    .withEmail("user@example.com")
                    .withPassword("")
                    .withAuthorities(Matchers.equalTo(UaaAuthority.USER_AUTHORITIES))
                    .withOrigin(OriginKeys.LOGIN_SERVER)
                    .withExternalId("user")
                    .withZoneId(mockIdentityZoneManager.getCurrentIdentityZoneId())));
        }
    }
}
