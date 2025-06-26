package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class AuthzAuthenticationManagerTests {
    private MockHttpSession mockHttpSession;
    private AuthzAuthenticationManager mgr;
    private UaaUserDatabase db;
    private ApplicationEventPublisher publisher;
    private static final String PASSWORD = "password";
    private UaaUser user;
    private PasswordEncoder encoder = new PasswordEncoderConfig().nonCachingPasswordEncoder();
    private String loginServerUserName = "loginServerUser".toLowerCase();
    private IdentityProviderProvisioning providerProvisioning;

    private ArgumentCaptor<ApplicationEvent> eventCaptor;

    @BeforeEach
    void setUp() {
        user = new UaaUser(getPrototype());
        providerProvisioning = mock(IdentityProviderProvisioning.class);
        db = mock(UaaUserDatabase.class);

        publisher = mock(ApplicationEventPublisher.class);
        eventCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        doNothing().when(publisher).publishEvent(eventCaptor.capture());
        AccountLoginPolicy mockAccountLoginPolicy = mock(AccountLoginPolicy.class);
        when(mockAccountLoginPolicy.isAllowed(any(), any())).thenReturn(true);

        mockHttpSession = new MockHttpSession();
        mgr = new AuthzAuthenticationManager(db, encoder, providerProvisioning, mockHttpSession);
        mgr.setApplicationEventPublisher(publisher);
        mgr.setOrigin(OriginKeys.UAA);
        mgr.setAccountLoginPolicy(mockAccountLoginPolicy);
    }

    private UaaUserPrototype getPrototype() {
        String id = new RandomValueStringGenerator().generate();
        return new UaaUserPrototype()
                .withId(id)
                .withUsername("auser")
                .withPassword(encoder.encode(PASSWORD))
                .withEmail("auser@blah.com")
                .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                .withGivenName("A")
                .withFamilyName("User")
                .withOrigin(OriginKeys.UAA)
                .withZoneId(IdentityZoneHolder.get().getId())
                .withExternalId(id)
                .withPasswordLastModified(new Date(System.currentTimeMillis()))
                .withVerified(true);
    }

    @Test
    void successfulAuthentication() {
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        Authentication result = mgr.authenticate(createAuthRequest("auser", "password"));
        assertThat(result).isNotNull();
        assertThat(result.getName()).isEqualTo("auser");
        assertThat(((UaaPrincipal) result.getPrincipal()).getName()).isEqualTo("auser");
        assertThat(((UaaAuthentication) result).getAuthenticationMethods()).containsExactlyInAnyOrder("pwd");

        List<ApplicationEvent> events = eventCaptor.getAllValues();
        assertThat(events.getFirst()).isInstanceOf(IdentityProviderAuthenticationSuccessEvent.class);
        assertThat(((IdentityProviderAuthenticationSuccessEvent) events.getFirst()).getUser().getUsername()).isEqualTo("auser");
    }

    @Test
    void unsuccessfulPasswordExpired() {
        IdentityProvider<UaaIdentityProviderDefinition> provider = new IdentityProvider<>();

        UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition(new PasswordPolicy(6, 128, 1, 1, 1, 1, 6), null);
        provider.setConfig(idpDefinition);

        when(providerProvisioning.retrieveByOriginIgnoreActiveFlag(eq(OriginKeys.UAA), anyString())).thenReturn(provider);

        Calendar oneYearAgoCal = Calendar.getInstance();
        oneYearAgoCal.add(Calendar.YEAR, -1);
        Date oneYearAgo = new Date(oneYearAgoCal.getTimeInMillis());
        user = new UaaUser(
                user.getId(),
                user.getUsername(),
                encoder.encode(PASSWORD),
                user.getPassword(),
                user.getAuthorities(),
                user.getGivenName(),
                user.getFamilyName(),
                oneYearAgo,
                oneYearAgo,
                OriginKeys.UAA,
                null,
                true,
                IdentityZoneHolder.get().getId(),
                user.getSalt(),
                oneYearAgo);
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        Authentication authentication = mgr.authenticate(createAuthRequest("auser", "password"));
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(SessionUtils.isPasswordChangeRequired(mockHttpSession)).isTrue();
    }

    @Test
    void unsuccessfulLoginServerUserAuthentication() {
        when(db.retrieveUserByName(loginServerUserName, OriginKeys.UAA)).thenReturn(null);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> mgr.authenticate(createAuthRequest(loginServerUserName, "")));
        verify(db, times(0)).updateLastLogonTime(anyString());
    }

    @Test
    void unsuccessfulLoginServerUserWithPasswordAuthentication() {
        when(db.retrieveUserByName(loginServerUserName, OriginKeys.UAA)).thenReturn(null);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> mgr.authenticate(createAuthRequest(loginServerUserName, "dadas")));
    }

    @Test
    void successfulAuthenticationReturnsTokenAndPublishesEvent() {
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        Authentication result = mgr.authenticate(createAuthRequest("auser", "password"));

        assertThat(result).isNotNull();
        assertThat(result.getName()).isEqualTo("auser");
        assertThat(((UaaPrincipal) result.getPrincipal()).getName()).isEqualTo("auser");

        verify(publisher).publishEvent(isA(IdentityProviderAuthenticationSuccessEvent.class));
    }

    @Test
    void invalidPasswordPublishesAuthenticationFailureEvent() {
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);

        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> mgr.authenticate(createAuthRequest("auser", "wrongpassword")));

        verify(publisher).publishEvent(isA(IdentityProviderAuthenticationFailureEvent.class));
        verify(publisher).publishEvent(isA(UserAuthenticationFailureEvent.class));
        verify(db, times(0)).updateLastLogonTime(anyString());
    }

    @Test
    void authenticationIsDeniedIfRejectedByLoginPolicy() {
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        AccountLoginPolicy lp = mock(AccountLoginPolicy.class);
        when(lp.isAllowed(any(UaaUser.class), any(Authentication.class))).thenReturn(false);
        mgr.setAccountLoginPolicy(lp);
        assertThatExceptionOfType(AuthenticationPolicyRejectionException.class).isThrownBy(() -> mgr.authenticate(createAuthRequest("auser", "password")));
        verify(db, times(0)).updateLastLogonTime(anyString());
    }

    @Test
    void missingUserPublishesNotFoundEvent() {
        when(db.retrieveUserByName("aguess", OriginKeys.UAA)).thenThrow(new UsernameNotFoundException("mocked"));
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> mgr.authenticate(createAuthRequest("aguess", "password")));
        verify(publisher).publishEvent(isA(UserNotFoundEvent.class));
    }

    @Test
    void successfulVerifyOriginAuthentication1() {
        mgr.setOrigin("test");
        user = user.modifySource("test", null);
        when(db.retrieveUserByName("auser", "test")).thenReturn(user);
        Authentication result = mgr.authenticate(createAuthRequest("auser", "password"));
        assertThat(result).isNotNull();
        assertThat(result.getName()).isEqualTo("auser");
        assertThat(((UaaPrincipal) result.getPrincipal()).getName()).isEqualTo("auser");
    }

    @Test
    void originAuthenticationFail() {
        when(db.retrieveUserByName("auser", "not UAA")).thenReturn(user);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> mgr.authenticate(createAuthRequest("auser", "password")));
    }

    @Test
    void unverifiedAuthenticationForOldUserSucceedsWhenAllowed() {
        mgr.setAllowUnverifiedUsers(true);
        user = new UaaUser(getPrototype().withLegacyVerificationBehavior(true));
        user.setVerified(false);
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        Authentication result = mgr.authenticate(createAuthRequest("auser", "password"));
        assertThat(result.getName()).isEqualTo("auser");
        assertThat(((UaaPrincipal) result.getPrincipal()).getName()).isEqualTo("auser");
    }

    @Test
    void unverifiedAuthenticationForNewUserFailsEvenWhenAllowed() {
        mgr.setAllowUnverifiedUsers(true);
        user.setVerified(false);
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        assertThatExceptionOfType(AccountNotVerifiedException.class).isThrownBy(() -> mgr.authenticate(createAuthRequest("auser", "password")));
        verify(publisher).publishEvent(isA(UnverifiedUserAuthenticationEvent.class));
    }

    @Test
    void authenticationWhenUserPasswordChangeRequired() {
        mgr.setAllowUnverifiedUsers(false);
        user.setPasswordChangeRequired(true);
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        Authentication authentication = mgr.authenticate(createAuthRequest("auser", "password"));
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(SessionUtils.isPasswordChangeRequired(mockHttpSession)).isTrue();
    }

    @Test
    void unverifiedAuthenticationFailsWhenNotAllowed() {
        mgr.setAllowUnverifiedUsers(false);
        user.setVerified(false);
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        assertThatExceptionOfType(AccountNotVerifiedException.class).isThrownBy(() -> mgr.authenticate(createAuthRequest("auser", "password")));
        verify(publisher).publishEvent(isA(UnverifiedUserAuthenticationEvent.class));
    }

    @Test
    void systemWidePasswordExpiry() {
        IdentityProvider<UaaIdentityProviderDefinition> provider = new IdentityProvider<>();
        UaaIdentityProviderDefinition idpDefinition = mock(UaaIdentityProviderDefinition.class);
        provider.setConfig(idpDefinition);
        when(providerProvisioning.retrieveByOriginIgnoreActiveFlag(eq(OriginKeys.UAA), anyString())).thenReturn(provider);
        PasswordPolicy policy = new PasswordPolicy();
        policy.setPasswordNewerThan(new Date(System.currentTimeMillis() + 1000));
        when(idpDefinition.getPasswordPolicy()).thenReturn(policy);
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        Authentication authentication = mgr.authenticate(createAuthRequest("auser", "password"));
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(SessionUtils.isPasswordChangeRequired(mockHttpSession)).isTrue();
    }

    @Test
    void systemWidePasswordExpiryWithPastDate() {
        IdentityProvider<UaaIdentityProviderDefinition> provider = new IdentityProvider<>();
        UaaIdentityProviderDefinition idpDefinition = mock(UaaIdentityProviderDefinition.class);
        provider.setConfig(idpDefinition);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(provider);
        PasswordPolicy policy = new PasswordPolicy();
        Date past = new Date(System.currentTimeMillis() - 10000000);
        policy.setPasswordNewerThan(past);
        when(idpDefinition.getPasswordPolicy()).thenReturn(policy);
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        mgr.authenticate(createAuthRequest("auser", "password"));
    }

    @Test
    void userIsLockedOutAfterNumberOfUnsuccessfulTriesIsExceeded() {
        AccountLoginPolicy lockoutPolicy = mock(PeriodLockoutPolicy.class);
        mgr.setAccountLoginPolicy(lockoutPolicy);
        when(db.retrieveUserByName("auser", OriginKeys.UAA)).thenReturn(user);
        Authentication authentication = createAuthRequest("auser", "password");
        when(lockoutPolicy.isAllowed(any(UaaUser.class), eq(authentication))).thenReturn(false);

        assertThatExceptionOfType(AuthenticationPolicyRejectionException.class).isThrownBy(() -> mgr.authenticate(authentication));

        assertThat(authentication.isAuthenticated()).isFalse();
        verify(publisher).publishEvent(isA(AuthenticationFailureLockedEvent.class));
    }

    private static AuthzAuthenticationRequest createAuthRequest(String username, String password) {
        Map<String, String> userdata = new HashMap<>();
        userdata.put("username", username);
        userdata.put("password", password);
        return new AuthzAuthenticationRequest(userdata, new UaaAuthenticationDetails(new MockHttpServletRequest()));
    }
}
