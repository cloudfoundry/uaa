package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.client.UaaClientDetailsUserDetailsService;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
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

    private UsernamePasswordAuthenticationToken getAuthenticationToken() {
        UsernamePasswordAuthenticationToken a = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(a.getDetails()).thenReturn(uaaAuthenticationDetails);
        Map<String, String[]> codeVerifier = new HashMap<>();
        codeVerifier.put("code_verifier", new String[] { "x" });
        when(uaaAuthenticationDetails.getParameterMap()).thenReturn(codeVerifier);
        return a;
    }

    @Test
    void provider_authenticate_client_with_one_password() {
        Authentication a = getToken(client.getClientId(), SECRET);
        testClientAuthentication(a);
    }

    @Test
    void provider_authenticate_client_without_password_public_string() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, "true");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken();
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("x", "x", Collections.emptyList(), client.getAdditionalInformation()), a);
        assertNotNull(a);
    }

    @Test
    void provider_authenticate_client_without_password_public_boolean() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken();
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("x", "x", Collections.emptyList(), client.getAdditionalInformation()), a);
        assertNotNull(a);
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
