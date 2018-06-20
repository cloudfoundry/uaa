package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthCodeToken;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;

public class PasswordGrantAuthenticationManagerTest {


    private PasswordGrantAuthenticationManager instance;

    private DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private RestTemplateConfig restTemplateConfig;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;
    private ClientServicesExtension clientDetailsService;

    private IdentityProvider idp;
    private OIDCIdentityProviderDefinition idpConfig;
    private ClientDetails clientDetails;

    @Before
    public void setUp() throws Exception {
        zoneAwareAuthzAuthenticationManager = mock(DynamicZoneAwareAuthenticationManager.class);
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        restTemplateConfig = mock(RestTemplateConfig.class);
        xoAuthAuthenticationManager = mock(XOAuthAuthenticationManager.class);
        clientDetailsService = mock(ClientServicesExtension.class);

        idp = mock(IdentityProvider.class);
        idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(idp.getConfig()).thenReturn(idpConfig);
        when(idp.isActive()).thenReturn(true);
        when(idp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);
        when(idpConfig.getTokenUrl()).thenReturn(new URL("http://localhost:8080/uaa/oauth/token"));
        when(idpConfig.getRelyingPartyId()).thenReturn("identity");
        when(idpConfig.getRelyingPartySecret()).thenReturn("identitysecret");

        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider","uaa")).thenReturn(idp);

        Authentication clientAuth = mock(Authentication.class);
        when(clientAuth.getName()).thenReturn("clientid");
        SecurityContextHolder.getContext().setAuthentication(clientAuth);
        clientDetails = mock(ClientDetails.class);
        when(clientDetails.getAdditionalInformation()).thenReturn(mock(Map.class));
        when(clientDetailsService.loadClientByClientId("clientid", "uaa")).thenReturn(clientDetails);

        instance = new PasswordGrantAuthenticationManager(zoneAwareAuthzAuthenticationManager, identityProviderProvisioning, restTemplateConfig, xoAuthAuthenticationManager, clientDetailsService);
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testPasswordGrantNoLoginHint() {
        Authentication auth = mock(Authentication.class);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
    }

    @Test
    public void testUaaPasswordGrant() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("uaa");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
    }

    @Test
    public void testOIDCPasswordGrant() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String,String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(),any(HttpMethod.class),any(HttpEntity.class),any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(),eq(new ParameterizedTypeReference<Map<String,String>>(){}));
        ArgumentCaptor<XOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(XOAuthCodeToken.class);
        verify(xoAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());

        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        assertNotNull(httpEntity);
        assertTrue(httpEntity.hasBody());
        assertTrue(httpEntity.getBody() instanceof MultiValueMap);
        MultiValueMap<String,String> body = (MultiValueMap<String, String>)httpEntity.getBody();
        assertEquals(4, body.size());
        assertEquals(Collections.singletonList("password"), body.get("grant_type"));
        assertEquals(Collections.singletonList("id_token"), body.get("response_type"));
        assertEquals(Collections.singletonList("marissa"), body.get("username"));
        assertEquals(Collections.singletonList("koala"), body.get("password"));

        HttpHeaders headers = httpEntity.getHeaders();
        assertEquals(Arrays.asList(APPLICATION_JSON), headers.getAccept());
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertNotNull(headers.get("Authorization"));
        assertEquals(1, headers.get("Authorization").size());
        assertThat(headers.get("Authorization").get(0), startsWith("Basic "));

        assertEquals("mytoken", tokenArgumentCaptor.getValue().getIdToken());
    }

    @Test
    public void testOIDCPasswordGrantProviderNotFound() {
        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider","uaa")).thenThrow(mock(DataAccessException.class));
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderNotFoundException e) {
            assertEquals("The origin provided in the login hint is invalid.", e.getMessage());
        }
    }

    @Test
    public void testOIDCPasswordGrantProviderNotActive() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.isActive()).thenReturn(false);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);

        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider","uaa")).thenReturn(localIdp);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderConfigurationException e) {
            assertEquals("The origin provided does not match an active OpenID Connect provider.", e.getMessage());
        }
    }

    @Test
    public void testOIDCPasswordGrantProviderTypeNotOidc() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.isActive()).thenReturn(true);
        when(localIdp.getType()).thenReturn(OriginKeys.SAML);

        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider","uaa")).thenReturn(localIdp);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderConfigurationException e) {
            assertEquals("The origin provided does not match an active OpenID Connect provider.", e.getMessage());
        }
    }

    @Test
    public void testOIDCPasswordGrantProviderDoesNotSupportPassword() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.isActive()).thenReturn(true);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(false);

        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider","uaa")).thenReturn(localIdp);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderConfigurationException e) {
            assertEquals("External OpenID Connect provider is not configured for password grant.", e.getMessage());
        }
    }

    @Test
    public void testOIDCPasswordGrantProviderNoRelyingPartyCredentials() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.isActive()).thenReturn(true);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);

        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider","uaa")).thenReturn(localIdp);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderConfigurationException e) {
            assertEquals("External OpenID Connect provider configuration is missing relyingPartyId or relyingPartySecret.", e.getMessage());
        }
    }

    @Test
    public void testOIDCPasswordGrantNoUserCredentials() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (BadCredentialsException e) {
            assertEquals("Request is missing username or password.", e.getMessage());
        }
    }

    @Test
    public void testOIDCPasswordGrantNoBody() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String,String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(false);
        when(rt.exchange(anyString(),any(HttpMethod.class),any(HttpEntity.class),any(ParameterizedTypeReference.class))).thenReturn(response);

        try {
            instance.authenticate(auth);
            fail();
        } catch (BadCredentialsException e) {
            assertEquals("Could not obtain id_token from external OpenID Connect provider.", e.getMessage());
        }
    }

    @Test
    public void testOIDCPasswordGrantNoIdToken() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String,String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.emptyMap());
        when(rt.exchange(anyString(),any(HttpMethod.class),any(HttpEntity.class),any(ParameterizedTypeReference.class))).thenReturn(response);

        try {
            instance.authenticate(auth);
            fail();
        } catch (BadCredentialsException e) {
            assertEquals("Could not obtain id_token from external OpenID Connect provider.", e.getMessage());
        }
    }

    @Test
    public void testOIDCPasswordGrantWithPrompts() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        UaaAuthenticationDetails uaaAuthDetails = mock(UaaAuthenticationDetails.class);
        Map<String, String[]> params = new HashMap<>();
        params.put("mfacode", new String[]{"123456"});
        params.put("multivalue", new String[]{"123456","654321"});
        params.put("emptyvalue", new String[0]);
        params.put("emptystring", new String[]{""});
        params.put("junk", new String[]{"true"});
        when(uaaAuthDetails.getParameterMap()).thenReturn(params);
        when(auth.getDetails()).thenReturn(uaaAuthDetails);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        List<Prompt> prompts = new ArrayList<>();
        prompts.add(new Prompt("username","text", "Email"));
        prompts.add(new Prompt("password","password", "Password"));
        prompts.add(new Prompt("passcode","password", "Temporary Authentication Code"));
        prompts.add(new Prompt("mfacode","password", "TOTP-Code"));
        prompts.add(new Prompt("multivalue","password", "TOTP-Code"));
        prompts.add(new Prompt("emptyvalue","password", "TOTP-Code"));
        prompts.add(new Prompt("emptystring","password", "TOTP-Code"));
        prompts.add(new Prompt("missingvalue","password", "TOTP-Code"));
        when(idpConfig.getPrompts()).thenReturn(prompts);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String,String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(),any(HttpMethod.class),any(HttpEntity.class),any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(),eq(new ParameterizedTypeReference<Map<String,String>>(){}));
        ArgumentCaptor<XOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(XOAuthCodeToken.class);
        verify(xoAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());

        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        assertNotNull(httpEntity);
        assertTrue(httpEntity.hasBody());
        assertTrue(httpEntity.getBody() instanceof MultiValueMap);
        MultiValueMap<String,String> body = (MultiValueMap<String, String>)httpEntity.getBody();
        assertEquals(5, body.size());
        assertEquals(Collections.singletonList("password"), body.get("grant_type"));
        assertEquals(Collections.singletonList("id_token"), body.get("response_type"));
        assertEquals(Collections.singletonList("marissa"), body.get("username"));
        assertEquals(Collections.singletonList("koala"), body.get("password"));
        assertEquals(Collections.singletonList("123456"), body.get("mfacode"));
        assertNull(body.get("passcode"));
        assertNull(body.get("multivalue"));
        assertNull(body.get("emptyvalue"));
        assertNull(body.get("emptystring"));
        assertNull(body.get("missingvalue"));

        HttpHeaders headers = httpEntity.getHeaders();
        assertEquals(Arrays.asList(APPLICATION_JSON), headers.getAccept());
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertNotNull(headers.get("Authorization"));
        assertEquals(1, headers.get("Authorization").size());
        assertThat(headers.get("Authorization").get(0), startsWith("Basic "));

        assertEquals("mytoken", tokenArgumentCaptor.getValue().getIdToken());
    }

    @Test
    public void testUaaPasswordGrant_allowedProvidersOnlyUaa() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("uaa", captor.getValue().getOrigin());
    }

    @Test
    public void testUaaPasswordGrant_allowedProvidersOnlyLdap() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("ldap"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("ldap", captor.getValue().getOrigin());
    }

    @Test
    public void testUaaPasswordGrant_allowedProvidersUaaAndLdap() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa","ldap"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNull(captor.getValue());
    }

    @Test
    public void testUaaPasswordGrant_defaultProviderUaa() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNull(captor.getValue());
    }
}
