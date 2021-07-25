package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
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

@ExtendWith(PollutionPreventionExtension.class)
class PasswordGrantAuthenticationManagerTest {

    private PasswordGrantAuthenticationManager instance;

    private DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private RestTemplateConfig restTemplateConfig;
    private ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private MultitenantClientServices clientDetailsService;
    private ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator;
    private ApplicationEventPublisher eventPublisher;

    private IdentityProvider idp;
    private IdentityProvider uaaProvider;
    private IdentityProvider ldapProvider;
    private OIDCIdentityProviderDefinition idpConfig;
    private ClientDetails clientDetails;

    @BeforeEach
    void setUp() throws Exception {
        zoneAwareAuthzAuthenticationManager = mock(DynamicZoneAwareAuthenticationManager.class);
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        restTemplateConfig = mock(RestTemplateConfig.class);
        externalOAuthAuthenticationManager = mock(ExternalOAuthAuthenticationManager.class);
        clientDetailsService = mock(MultitenantClientServices.class);
        externalOAuthProviderConfigurator = mock(ExternalOAuthProviderConfigurator.class);

        idp = mock(IdentityProvider.class);
        idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(idp.getOriginKey()).thenReturn("oidcprovider");
        when(idp.getConfig()).thenReturn(idpConfig);
        when(idp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);
        when(idpConfig.getTokenUrl()).thenReturn(new URL("http://localhost:8080/uaa/oauth/token"));
        when(idpConfig.getRelyingPartyId()).thenReturn("identity");
        when(idpConfig.getRelyingPartySecret()).thenReturn("identitysecret");

        uaaProvider = mock(IdentityProvider.class);
        when(uaaProvider.getType()).thenReturn(OriginKeys.UAA);
        when(uaaProvider.getOriginKey()).thenReturn(OriginKeys.UAA);
        ldapProvider = mock(IdentityProvider.class);
        when(ldapProvider.getType()).thenReturn(OriginKeys.LDAP);
        when(ldapProvider.getOriginKey()).thenReturn(OriginKeys.LDAP);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(idp, uaaProvider, ldapProvider));
        when(externalOAuthProviderConfigurator.retrieveByOrigin("oidcprovider", "uaa")).thenReturn(idp);

        Authentication clientAuth = mock(Authentication.class);
        when(clientAuth.getName()).thenReturn("clientid");
        SecurityContextHolder.getContext().setAuthentication(clientAuth);
        clientDetails = mock(ClientDetails.class);
        when(clientDetails.getAdditionalInformation()).thenReturn(mock(Map.class));
        when(clientDetailsService.loadClientByClientId("clientid", "uaa")).thenReturn(clientDetails);

        instance = new PasswordGrantAuthenticationManager(zoneAwareAuthzAuthenticationManager, identityProviderProvisioning, restTemplateConfig, externalOAuthAuthenticationManager, clientDetailsService, externalOAuthProviderConfigurator);
        IdentityZoneHolder.clear();
        eventPublisher = mock(ApplicationEventPublisher.class);
        instance.setApplicationEventPublisher(eventPublisher);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    void testPasswordGrantNoLoginHint() {
        Authentication auth = mock(Authentication.class);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
    }

    @Test
    void testUaaPasswordGrant() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("uaa");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
    }

    @Test
    void testOIDCPasswordGrant() {
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
        ArgumentCaptor<ExternalOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
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
        assertEquals(Collections.singletonList(APPLICATION_JSON), headers.getAccept());
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertNotNull(headers.get("Authorization"));
        assertEquals(1, headers.get("Authorization").size());
        assertThat(headers.get("Authorization").get(0), startsWith("Basic "));
        assertNull(headers.get("X-Forwarded-For"));

        assertEquals("mytoken", tokenArgumentCaptor.getValue().getIdToken());
    }

    @Test
    void testOIDCPasswordGrantWithForwardHeader() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getOrigin()).thenReturn("203.0.113.1");
        when(auth.getDetails()).thenReturn(details);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String,String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(),any(HttpMethod.class),any(HttpEntity.class),any(ParameterizedTypeReference.class))).thenReturn(response);

        when(idpConfig.isSetForwardHeader()).thenReturn(true);

        instance.authenticate(auth);

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(),eq(new ParameterizedTypeReference<Map<String,String>>(){}));
        ArgumentCaptor<ExternalOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
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
        assertEquals(Collections.singletonList(APPLICATION_JSON), headers.getAccept());
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertNotNull(headers.get("Authorization"));
        assertEquals(1, headers.get("Authorization").size());
        assertThat(headers.get("Authorization").get(0), startsWith("Basic "));
        assertNotNull(headers.get("X-Forwarded-For"));
        assertEquals(1, headers.get("X-Forwarded-For").size());
        assertEquals("203.0.113.1", headers.get("X-Forwarded-For").get(0));

        assertEquals("mytoken", tokenArgumentCaptor.getValue().getIdToken());
    }

    @Test
    void testOIDCPasswordGrantInvalidLogin() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala1");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String,String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        HttpClientErrorException exception = mock(HttpClientErrorException.class);
        when(rt.exchange(anyString(),any(HttpMethod.class),any(HttpEntity.class),any(ParameterizedTypeReference.class))).thenThrow(exception);

        try {
            instance.authenticate(auth);
            fail("No Exception thrown.");
        } catch (BadCredentialsException ignored) {
        }

        ArgumentCaptor<AbstractUaaEvent> eventArgumentCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(eventPublisher, times(1)).publishEvent(eventArgumentCaptor.capture());

        assertEquals(1, eventArgumentCaptor.getAllValues().size());
        assertTrue(eventArgumentCaptor.getValue() instanceof IdentityProviderAuthenticationFailureEvent);
    }

    @Test
    void testOIDCPasswordGrantProviderNotFound() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider2");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderConfigurationException e) {
            assertEquals("The origin provided in the login_hint does not match an active Identity Provider, that supports password grant.", e.getMessage());
        }
    }

    @Test
    void testOIDCPasswordGrantProviderTypeNotOidc() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.isActive()).thenReturn(true);
        when(localIdp.getType()).thenReturn(OriginKeys.SAML);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderConfigurationException e) {
            assertEquals("The origin provided in the login_hint does not match an active Identity Provider, that supports password grant.", e.getMessage());
        }
    }

    @Test
    void testOIDCPasswordGrantProviderDoesNotSupportPassword() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(false);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderConfigurationException e) {
            assertEquals("The origin provided in the login_hint does not match an active Identity Provider, that supports password grant.", e.getMessage());
        }
    }

    @Test
    void testOIDCPasswordGrantProviderNoRelyingPartyCredentials() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        when(externalOAuthProviderConfigurator.retrieveByOrigin("oidcprovider", "uaa")).thenReturn(localIdp);
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
    void testOIDCPasswordGrantNoUserCredentials() {
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
    void testOIDCPasswordGrantNoBody() {
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
    void testOIDCPasswordGrantNoIdToken() {
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
    void testOIDCPasswordGrantWithPrompts() {
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
        ArgumentCaptor<ExternalOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
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
        assertEquals(Collections.singletonList(APPLICATION_JSON), headers.getAccept());
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertNotNull(headers.get("Authorization"));
        assertEquals(1, headers.get("Authorization").size());
        assertThat(headers.get("Authorization").get(0), startsWith("Basic "));

        assertEquals("mytoken", tokenArgumentCaptor.getValue().getIdToken());
    }

    @Test
    void testUaaPasswordGrant_allowedProvidersOnlyUaa() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("uaa", captor.getValue().getOrigin());
    }

    @Test
    void testUaaPasswordGrant_allowedProvidersOnlyLdap() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("ldap"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("ldap", captor.getValue().getOrigin());
    }

    @Test
    void testUaaPasswordGrant_allowedProvidersUaaAndLdap() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa","ldap"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(0)).setLoginHint(any(), any());
    }

    @Test
    void testUaaPasswordGrant_defaultProviderUaa() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(0)).setLoginHint(any(), any());
    }

    @Test
    void testPasswordGrant_NoLoginHintWithDefaultUaa() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInformation);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("uaa", captor.getValue().getOrigin());
    }

    @Test
    void testOIDCPasswordGrant_NoLoginHintWithDefaultOIDC() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String,String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(),any(HttpMethod.class),any(HttpEntity.class),any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(),eq(new ParameterizedTypeReference<Map<String,String>>(){}));
        ArgumentCaptor<ExternalOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
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
        assertEquals(Collections.singletonList(APPLICATION_JSON), headers.getAccept());
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertNotNull(headers.get("Authorization"));
        assertEquals(1, headers.get("Authorization").size());
        assertThat(headers.get("Authorization").get(0), startsWith("Basic "));

        assertEquals("mytoken", tokenArgumentCaptor.getValue().getIdToken());
    }

    @Test
    void testOIDCPasswordGrant_LoginHintOidcOverridesDefaultUaa() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
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

        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), any(HttpEntity.class),eq(new ParameterizedTypeReference<Map<String,String>>(){}));
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(any(ExternalOAuthCodeToken.class));
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());
    }

    @Test
    void testOIDCPasswordGrant_LoginHintUaaOverridesDefaultOidc() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("uaa");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInformation);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider");

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("uaa", captor.getValue().getOrigin());
    }

    @Test
    void testOIDCPasswordGrant_NoLoginHintDefaultNotAllowedSingleIdpOIDC() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("oidcprovider"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInfo);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String,String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(),any(HttpMethod.class),any(HttpEntity.class),any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), any(HttpEntity.class),eq(new ParameterizedTypeReference<Map<String,String>>(){}));
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(any(ExternalOAuthCodeToken.class));
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());
    }

    @Test
    void testOIDCPasswordGrant_NoLoginHintDefaultNotAllowedSingleIdpDoesNotSupportPassword() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("oidcprovider"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInfo);
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(false);
        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        when(externalOAuthProviderConfigurator.retrieveByOrigin("oidcprovider","uaa")).thenReturn(localIdp);

        try {
            instance.authenticate(auth);
            fail();
        } catch (BadCredentialsException e) {
            assertEquals("The client is not authorized for any identity provider that supports password grant.", e.getMessage());
        }
    }

    @Test
    void testOIDCPasswordGrant_NoLoginHintDefaultNotAllowedSingleIdpUAA() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInfo);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("uaa", captor.getValue().getOrigin());
    }

    @Test
    void testOIDCPasswordGrant_NoLoginHintDefaultNotAllowedChainedAuth() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa", "ldap"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInfo);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        verify(zoneAwareAuthzAuthenticationManager, times(0)).setLoginHint(any(), any());
    }

    @Test
    void testOIDCPasswordGrant_NoLoginHintDefaultNotAllowedMultipleIdpsWithUaa() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider2");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa", "oidcprovider"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInfo);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("uaa", captor.getValue().getOrigin());
    }

    @Test
    void testOIDCPasswordGrant_NoLoginHintDefaultNotAllowedMultipleIdpsOnlyOIDC() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider3");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("oidcprovider", "oidcprovider2"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInfo);

        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider2");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, idp, localIdp));

        try {
            instance.authenticate(auth);
            fail();
        } catch (BadCredentialsException e) {
            assertEquals("The client is authorized for multiple identity providers that support password grant and could not determine which identity provider to use.", e.getMessage());
        }
    }

    @Test
    void testPasswordGrant_NoLoginHintNoDefaultTriesChainedAuth() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        verify(zoneAwareAuthzAuthenticationManager, times(0)).setLoginHint(any(), any());
    }

    @Test
    void testOIDCPasswordGrant_LoginHintProviderNotAllowed() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider2");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa", "oidcprovider"));
        when(clientDetails.getAdditionalInformation()).thenReturn(additionalInfo);

        try {
            instance.authenticate(auth);
            fail();
        } catch (ProviderConfigurationException e) {
            assertEquals("Client is not authorized for specified user's identity provider.", e.getMessage());
        }
    }
}
