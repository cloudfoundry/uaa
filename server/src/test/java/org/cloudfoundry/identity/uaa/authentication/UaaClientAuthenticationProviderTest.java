package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.account.UaaUserDetails;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.client.UaaClientDetailsUserDetailsService;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class UaaClientAuthenticationProviderTest {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private MultitenantJdbcClientDetailsService jdbcClientDetailsService;
    private ClientDetails client;
    private ClientDetailsAuthenticationProvider authenticationProvider;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUpForClientTests() {
        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());

        jdbcClientDetailsService = new MultitenantJdbcClientDetailsService(jdbcTemplate, mockIdentityZoneManager, passwordEncoder);
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        clientDetailsService.setPasswordEncoder(passwordEncoder);
        client = createClient();
        authenticationProvider = new ClientDetailsAuthenticationProvider(clientDetailsService, passwordEncoder);
    }

    public BaseClientDetails createClient() {
        return createClient(null, null);
    }

    public BaseClientDetails createClient(String addtionalKey, Object value) {
        BaseClientDetails details = new BaseClientDetails(generator.generate(), "", "", "client_credentials", "uaa.resource");
        details.setClientSecret(SECRET);
        if (addtionalKey != null) {
            details.addAdditionalInformation(addtionalKey, value);
        }
        jdbcClientDetailsService.addClientDetails(details);
        return details;
    }

    private UsernamePasswordAuthenticationToken getToken(String clientId, String clientSecret) {
        return new UsernamePasswordAuthenticationToken(clientId, clientSecret);
    }

    private void testClientAuthentication(Authentication a) {
        Authentication authentication = authenticationProvider.authenticate(a);
        assertNotNull(authentication);
        assertTrue(authentication.isAuthenticated());
    }

    private UsernamePasswordAuthenticationToken getAuthenticationToken(String grant_type) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("code_verifier","E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        request.addParameter("code", "1234567890");
        request.addParameter("client_id", "id");
        request.addParameter("redirect_uri",  "http://localhost:8080/uaa");
        request.addParameter("grant_type",  grant_type);
        return getAuthenticationToken(request);
    }

    private UsernamePasswordAuthenticationToken getAuthenticationToken(HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authentication = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = new UaaAuthenticationDetails(request);
        when(authentication.getDetails()).thenReturn(uaaAuthenticationDetails);
        return authentication;
    }

    @Test
    void provider_authenticate_client_with_one_password() {
        Authentication a = getToken(client.getClientId(), SECRET);
        testClientAuthentication(a);
    }

    @Test
    void provider_authenticate_client_without_password_public_string() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, "true");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("authorization_code");
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation()), a);
        assertNotNull(a);
    }

    @Test
    void provider_refresh_client_without_password_public_boolean() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "id");
        request.addParameter("refresh_token",  "1234567890");
        request.addParameter("grant_type",  "refresh_token");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation()), a);
        assertNotNull(a);
    }

    @Test
    void provider_refresh_client_with_password_inAuthorizationHeader_public_boolean() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addHeader("Authorization", "client:secret");
        request.addParameter("client_id", "id");
        request.addParameter("refresh_token",  "1234567890");
        request.addParameter("grant_type",  "refresh_token");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);
        assertThrows(BadCredentialsException.class, () -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation()), a));
    }

    @Test
    void provider_refresh_client_without_wrong_endpoint() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/authorize");
        request.addParameter("client_id", "id");
        request.addParameter("refresh_token",  "1234567890");
        request.addParameter("grant_type",  "refresh_token");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);
        assertThrows(BadCredentialsException.class, () -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation()), a));
    }

    @Test
    void provider_authenticate_client_without_password_public_boolean() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("authorization_code");
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation()), a);
        assertNotNull(a);
    }

    @Test
    void provider_authenticate_client_without_password_public_wrong_grant_type() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("client_credentials");
        assertThrows(BadCredentialsException.class, () -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret secret2", Collections.emptyList(), client.getAdditionalInformation()), a));
    }

    @Test
    void provider_authenticate_no_details() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("authorization_code");
        UserDetails userDetails = new UaaUserDetails(new UaaUser("client", "secret", "mail@user", "", ""));
        assertThrows(BadCredentialsException.class, () -> authenticationProvider.additionalAuthenticationChecks(userDetails, a));
    }

    @Test
    void provider_authenticate_no_authenticationDetails() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("authorization_code");
        when(a.getDetails()).thenReturn(null);
        assertThrows(BadCredentialsException.class, () -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret secret2", Collections.emptyList(), client.getAdditionalInformation()), a));
    }

    @Test
    void provider_authenticate_client_without_password_public_missing_code() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(a.getDetails()).thenReturn(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = new HashMap<>();
        when(uaaAuthenticationDetails.getParameterMap()).thenReturn(requestParameters);
        assertThrows(BadCredentialsException.class, () -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation()), a));
    }

    @Test
    void provider_authenticate_client_without_password_public_false() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, false);
        UsernamePasswordAuthenticationToken a = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(a.getDetails()).thenReturn(uaaAuthenticationDetails);
        assertThrows(BadCredentialsException.class, () ->testClientAuthentication(a));
    }

    @Test
    void provider_authenticate_client_with_two_passwords_test_1() {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2", IdentityZoneHolder.get().getId());
        testClientAuthentication(getToken(client.getClientId(), SECRET));
    }

    @Test
    void provider_authenticate_client_with_two_passwords_test_2() {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2", IdentityZoneHolder.get().getId());
        testClientAuthentication(getToken(client.getClientId(), "secret2"));
    }

    @Test
    void provider_authenticate_client_with_two_passwords_test_3() {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2", IdentityZoneHolder.get().getId());
        assertThrows(AuthenticationException.class, () -> testClientAuthentication(getToken(client.getClientId(), "secret3")));
    }
}
