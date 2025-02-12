package org.cloudfoundry.identity.uaa.authentication.manager;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelperX5tTest;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
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
    private ApplicationEventPublisher eventPublisher;

    private IdentityProvider idp;
    private IdentityProvider uaaProvider;
    private IdentityProvider ldapProvider;
    private OIDCIdentityProviderDefinition idpConfig;
    private UaaClient uaaClient;

    @BeforeEach
    void setUp() throws Exception {
        zoneAwareAuthzAuthenticationManager = mock(DynamicZoneAwareAuthenticationManager.class);
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        restTemplateConfig = mock(RestTemplateConfig.class);
        externalOAuthAuthenticationManager = mock(ExternalOAuthAuthenticationManager.class);

        idp = mock(IdentityProvider.class);
        idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(idp.getOriginKey()).thenReturn("oidcprovider");
        when(idp.getConfig()).thenReturn(idpConfig);
        when(idp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idp.isActive()).thenReturn(true);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);
        when(idpConfig.getTokenUrl()).thenReturn(new URL("http://localhost:8080/uaa/oauth/token"));
        when(idpConfig.getRelyingPartyId()).thenReturn("identity");
        when(idpConfig.getRelyingPartySecret()).thenReturn("identitysecret");

        uaaProvider = mock(IdentityProvider.class);
        when(uaaProvider.getType()).thenReturn(OriginKeys.UAA);
        when(uaaProvider.getOriginKey()).thenReturn(OriginKeys.UAA);
        when(uaaProvider.isActive()).thenReturn(true);
        ldapProvider = mock(IdentityProvider.class);
        when(ldapProvider.getType()).thenReturn(OriginKeys.LDAP);
        when(ldapProvider.getOriginKey()).thenReturn(OriginKeys.LDAP);
        when(ldapProvider.isActive()).thenReturn(true);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(idp, uaaProvider, ldapProvider));
        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider", "uaa")).thenReturn(idp);
        when(identityProviderProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(uaaProvider);
        when(identityProviderProvisioning.retrieveByOrigin("ldap", "uaa")).thenReturn(ldapProvider);

        Authentication clientAuth = mock(Authentication.class);
        when(clientAuth.getName()).thenReturn("clientid");
        SecurityContextHolder.getContext().setAuthentication(clientAuth);
        uaaClient = mock(UaaClient.class);
        when(clientAuth.getPrincipal()).thenReturn(uaaClient);
        when(uaaClient.getAdditionalInformation()).thenReturn(mock(Map.class));

        instance = new PasswordGrantAuthenticationManager(zoneAwareAuthzAuthenticationManager, identityProviderProvisioning, restTemplateConfig, externalOAuthAuthenticationManager);
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
    void passwordGrantNoLoginHint() {
        Authentication auth = mock(Authentication.class);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        verify(identityProviderProvisioning, times(0)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(1)).retrieveActive(any());
    }

    @Test
    void uaaPasswordGrant() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("uaa");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
    }

    @Test
    void oidcPasswordGrant() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        ArgumentCaptor<ExternalOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());
        verify(identityProviderProvisioning, times(1)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(0)).retrieveActive(any());

        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        assertThat(httpEntity).isNotNull();
        assertThat(httpEntity.hasBody()).isTrue();
        assertThat(httpEntity.getBody()).isInstanceOf(MultiValueMap.class);
        MultiValueMap<String, String> body = (MultiValueMap<String, String>) httpEntity.getBody();
        assertThat(body).hasSize(4)
                .containsEntry("grant_type", Collections.singletonList("password"))
                .containsEntry("response_type", Collections.singletonList("id_token"))
                .containsEntry("username", Collections.singletonList("marissa"))
                .containsEntry("password", Collections.singletonList("koala"));

        HttpHeaders headers = httpEntity.getHeaders();
        assertThat(headers.getAccept()).isEqualTo(Collections.singletonList(APPLICATION_JSON));
        assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertThat(headers).containsKey("Authorization");
        assertThat(headers.get("Authorization")).hasSize(1);
        assertThat(headers.get("Authorization").get(0)).startsWith("Basic ");
        assertThat(headers).doesNotContainKey("X-Forwarded-For");

        assertThat(tokenArgumentCaptor.getValue().getIdToken()).isEqualTo("mytoken");
    }

    @Test
    void oidcPasswordGrantWithForwardHeader() {
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

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        when(idpConfig.isSetForwardHeader()).thenReturn(true);

        instance.authenticate(auth);

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        ArgumentCaptor<ExternalOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());
        verify(identityProviderProvisioning, times(1)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(0)).retrieveActive(any());

        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        assertThat(httpEntity).isNotNull();
        assertThat(httpEntity.hasBody()).isTrue();
        assertThat(httpEntity.getBody()).isInstanceOf(MultiValueMap.class);
        MultiValueMap<String, String> body = (MultiValueMap<String, String>) httpEntity.getBody();
        assertThat(body).hasSize(4)
                .containsEntry("grant_type", Collections.singletonList("password"))
                .containsEntry("response_type", Collections.singletonList("id_token"))
                .containsEntry("username", Collections.singletonList("marissa"))
                .containsEntry("password", Collections.singletonList("koala"));

        HttpHeaders headers = httpEntity.getHeaders();
        assertThat(headers.getAccept()).isEqualTo(Collections.singletonList(APPLICATION_JSON));
        assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertThat(headers).containsKey("Authorization");
        assertThat(headers.get("Authorization")).hasSize(1);
        assertThat(headers.get("Authorization").get(0)).startsWith("Basic ");
        assertThat(headers).containsKey("X-Forwarded-For");
        assertThat(headers.get("X-Forwarded-For")).hasSize(1);
        assertThat(headers.get("X-Forwarded-For").get(0)).isEqualTo("203.0.113.1");

        assertThat(tokenArgumentCaptor.getValue().getIdToken()).isEqualTo("mytoken");
    }

    @Test
    void oidcPasswordGrantInvalidLogin() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala1");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        HttpClientErrorException exception = mock(HttpClientErrorException.class);
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenThrow(exception);

        try {
            instance.authenticate(auth);
            fail("No Exception thrown.");
        } catch (BadCredentialsException ignored) {
        }

        ArgumentCaptor<AbstractUaaEvent> eventArgumentCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(eventPublisher, times(1)).publishEvent(eventArgumentCaptor.capture());

        assertThat(eventArgumentCaptor.getAllValues()).hasSize(1);
        assertThat(eventArgumentCaptor.getValue()).isInstanceOf(IdentityProviderAuthenticationFailureEvent.class);
    }

    @Test
    void oidcPasswordGrantProviderNotFound() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider2");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("The origin provided in the login_hint does not match an active Identity Provider, that supports password grant.");
        }
    }

    @Test
    void oidcPasswordGrantProviderNotFoundInDB() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider2");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);
        when(identityProviderProvisioning.retrieveByOrigin(any(), any())).thenThrow(new EmptyResultDataAccessException(1));

        try {
            instance.authenticate(auth);
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("The origin provided in the login_hint does not match an active Identity Provider, that supports password grant.");
        }
    }

    @Test
    void oidcPasswordGrantProviderTypeNotOidc() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.isActive()).thenReturn(true);
        when(localIdp.getType()).thenReturn(OriginKeys.SAML);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider", "uaa")).thenReturn(localIdp);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("The origin provided in the login_hint does not match an active Identity Provider, that supports password grant.");
        }
    }

    @Test
    void oidcPasswordGrantProviderDoesNotSupportPassword() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(localIdp.isActive()).thenReturn(true);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(false);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider", "uaa")).thenReturn(localIdp);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("The origin provided in the login_hint does not match an active Identity Provider, that supports password grant.");
        }
    }

    @Test
    void oidcPasswordGrantProviderNoRelyingPartyCredentials() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(localIdp.isActive()).thenReturn(true);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider", "uaa")).thenReturn(localIdp);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("External OpenID Connect provider configuration is missing relyingPartyId.");
        }
    }

    @Test
    void oidcPasswordGrantProviderFailedInOidcMetadataUpdate() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition localIdpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(localIdp.isActive()).thenReturn(true);
        when(localIdp.getConfig()).thenReturn(localIdpConfig);
        when(localIdpConfig.isPasswordGrantEnabled()).thenReturn(true);
        when(localIdpConfig.getRelyingPartyId()).thenReturn("oidcprovider");
        when(localIdpConfig.getRelyingPartySecret()).thenReturn("");

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider", "uaa")).thenReturn(localIdp);
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("External OpenID Connect metadata is missing after discovery update.");
        }
    }

    @Test
    void oidcPasswordGrantProviderJwtClientCredentials() throws ParseException, JOSEException {
        // Given
        mockKeyInfoService();
        /* mock idp config using jwt client authentication */
        when(idpConfig.getRelyingPartySecret()).thenReturn(null);
        when(idpConfig.getJwtClientAuthentication()).thenReturn(true);
        when(idpConfig.getScopes()).thenReturn(Arrays.asList("openid", "email"));
        /* hint mock to use idp for password grant */
        Authentication auth = getAuthenticationWithUaaHint();
        /* HTTP mock */
        RestTemplate rt = getRestTemplate();

        // When
        instance.authenticate(auth);
        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);

        // Then
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        LinkedMultiValueMap<String, Object> httpEntityBody = (LinkedMultiValueMap) httpEntity.getBody();
        assertThat(httpEntityBody).containsKey("client_assertion")
                .containsKey("client_assertion_type")
                .containsEntry("client_assertion_type", Collections.singletonList(JwtClientAuthentication.GRANT_TYPE))
                .containsKey("scope")
                .containsEntry("scope", Collections.singletonList("openid email"));
        /* verify client assertion according OIDC private_key_jwt */
        JWTClaimsSet jwtClaimsSet = JWTParser.parse((String) httpEntityBody.get("client_assertion").get(0)).getJWTClaimsSet();
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList("http://localhost:8080/uaa/oauth/token"));
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("identity");
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("identity");
    }

    @Test
    void oidcPasswordGrantNoUserCredentials() throws MalformedURLException {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(idpConfig.getTokenUrl()).thenReturn(null).thenReturn(new URL("http://localhost:8080/uaa/oauth/token"));
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (BadCredentialsException e) {
            assertThat(e.getMessage()).isEqualTo("Request is missing username or password.");
        }
    }

    @Test
    void oidcPasswordGrantNoBody() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(false);
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (BadCredentialsException e) {
            assertThat(e.getMessage()).isEqualTo("Could not obtain id_token from external OpenID Connect provider.");
        }
    }

    @Test
    void oidcPasswordGrantNoIdToken() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.emptyMap());
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (BadCredentialsException e) {
            assertThat(e.getMessage()).isEqualTo("Could not obtain id_token from external OpenID Connect provider.");
        }
    }

    @Test
    void oidcPasswordGrantWithPrompts() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        UaaAuthenticationDetails uaaAuthDetails = mock(UaaAuthenticationDetails.class);
        Map<String, String[]> params = new HashMap<>();
        params.put("multivalue", new String[]{"123456", "654321"});
        params.put("emptyvalue", new String[0]);
        params.put("emptystring", new String[]{""});
        params.put("junk", new String[]{"true"});
        when(uaaAuthDetails.getParameterMap()).thenReturn(params);
        when(auth.getDetails()).thenReturn(uaaAuthDetails);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        List<Prompt> prompts = new ArrayList<>();
        prompts.add(new Prompt("username", "text", "Email"));
        prompts.add(new Prompt("password", "password", "Password"));
        prompts.add(new Prompt("passcode", "password", "Temporary Authentication Code"));
        prompts.add(new Prompt("multivalue", "password", "TOTP-Code"));
        prompts.add(new Prompt("emptyvalue", "password", "TOTP-Code"));
        prompts.add(new Prompt("emptystring", "password", "TOTP-Code"));
        prompts.add(new Prompt("missingvalue", "password", "TOTP-Code"));
        when(idpConfig.getPrompts()).thenReturn(prompts);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        ArgumentCaptor<ExternalOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());
        verify(identityProviderProvisioning, times(1)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(0)).retrieveActive(any());

        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        assertThat(httpEntity).isNotNull();
        assertThat(httpEntity.hasBody()).isTrue();
        assertThat(httpEntity.getBody()).isInstanceOf(MultiValueMap.class);
        MultiValueMap<String, String> body = (MultiValueMap<String, String>) httpEntity.getBody();
        assertThat(body).hasSize(4)
                .containsEntry("grant_type", Collections.singletonList("password"))
                .containsEntry("response_type", Collections.singletonList("id_token"))
                .containsEntry("username", Collections.singletonList("marissa"))
                .containsEntry("password", Collections.singletonList("koala"))
                .doesNotContainKey("passcode")
                .doesNotContainKey("multivalue")
                .doesNotContainKey("emptyvalue")
                .doesNotContainKey("emptystring")
                .doesNotContainKey("missingvalue");

        HttpHeaders headers = httpEntity.getHeaders();
        assertThat(headers.getAccept()).isEqualTo(Collections.singletonList(APPLICATION_JSON));
        assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertThat(headers).containsKey("Authorization");
        assertThat(headers.get("Authorization")).hasSize(1);
        assertThat(headers.get("Authorization").get(0)).startsWith("Basic ");

        assertThat(tokenArgumentCaptor.getValue().getIdToken()).isEqualTo("mytoken");
    }

    @Test
    void uaaPasswordGrantAllowedProvidersOnlyUaa() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertThat(captor.getValue()).isNotNull();
        assertThat(captor.getValue().getOrigin()).isEqualTo("uaa");
    }

    @Test
    void uaaPasswordGrantAllowedProvidersOnlyLdap() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("ldap"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertThat(captor.getValue()).isNotNull();
        assertThat(captor.getValue().getOrigin()).isEqualTo("ldap");
    }

    @Test
    void uaaPasswordGrantAllowedProvidersUaaAndLdap() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa", "ldap"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInformation);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        verify(zoneAwareAuthzAuthenticationManager, times(0)).setLoginHint(any(), any());
    }

    @Test
    void uaaPasswordGrantDefaultProviderUaa() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        verify(zoneAwareAuthzAuthenticationManager, times(0)).setLoginHint(any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {OriginKeys.UAA, OriginKeys.LDAP})
    void passwordGrantNoLoginHintWithDefaultUaaOrLdap(final String loginHintOrigin) {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(loginHintOrigin));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInformation);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider(loginHintOrigin);

        instance.authenticate(auth);

        /* should not read all in the zone during lookup of possible providers
         * - "uaa" or "ldap" is used, but not as login hint */
        final String idzId = IdentityZoneHolder.get().getId();
        verify(identityProviderProvisioning, times(0)).retrieveActive(idzId);
        verify(identityProviderProvisioning, times(1)).retrieveByOrigin(loginHintOrigin, idzId);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertThat(captor.getValue()).isNotNull();
        assertThat(captor.getValue().getOrigin()).isEqualTo(loginHintOrigin);
    }

    @Test
    void oidcPasswordGrantNoLoginHintWithDefaultOIDC() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        ArgumentCaptor<ExternalOAuthCodeToken> tokenArgumentCaptor = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(tokenArgumentCaptor.capture());
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());
        verify(identityProviderProvisioning, times(1)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(0)).retrieveActive(any());

        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        assertThat(httpEntity).isNotNull();
        assertThat(httpEntity.hasBody()).isTrue();
        assertThat(httpEntity.getBody()).isInstanceOf(MultiValueMap.class);
        MultiValueMap<String, String> body = (MultiValueMap<String, String>) httpEntity.getBody();
        assertThat(body).hasSize(4)
                .containsEntry("grant_type", Collections.singletonList("password"))
                .containsEntry("response_type", Collections.singletonList("id_token"))
                .containsEntry("username", Collections.singletonList("marissa"))
                .containsEntry("password", Collections.singletonList("koala"));

        HttpHeaders headers = httpEntity.getHeaders();
        assertThat(headers.getAccept()).isEqualTo(Collections.singletonList(APPLICATION_JSON));
        assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertThat(headers).containsKey("Authorization");
        assertThat(headers.get("Authorization")).hasSize(1);
        assertThat(headers.get("Authorization").get(0)).startsWith("Basic ");

        assertThat(tokenArgumentCaptor.getValue().getIdToken()).isEqualTo("mytoken");
    }

    @Test
    void oidcPasswordGrantLoginHintOidcOverridesDefaultUaa() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), any(HttpEntity.class), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(any(ExternalOAuthCodeToken.class));
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());
        verify(identityProviderProvisioning, times(1)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(0)).retrieveActive(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {OriginKeys.UAA, OriginKeys.LDAP})
    void oidcPasswordGrantLoginHintUaaOrLdapOverridesDefaultOidc(final String loginHintOrigin) {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn(loginHintOrigin);
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(loginHintOrigin));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInformation);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider");

        instance.authenticate(auth);

        // should read only "uaa" or "ldap" IdP during lookup of possible providers
        final String idzId = IdentityZoneHolder.get().getId();
        verify(identityProviderProvisioning, times(0)).retrieveActive(idzId);
        verify(identityProviderProvisioning, times(1)).retrieveByOrigin(loginHintOrigin, idzId);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertThat(captor.getValue()).isNotNull();
        assertThat(captor.getValue().getOrigin()).isEqualTo(loginHintOrigin);
    }

    @Test
    void oidcPasswordGrantNoLoginHintDefaultNotAllowedSingleIdpOIDC() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("oidcprovider"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInfo);

        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        instance.authenticate(auth);

        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), any(HttpEntity.class), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(any(ExternalOAuthCodeToken.class));
        verify(zoneAwareAuthzAuthenticationManager, times(0)).authenticate(any());
        verify(identityProviderProvisioning, atLeast(1)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(1)).retrieveActive(any());
    }

    @Test
    void oidcPasswordGrantNoLoginHintDefaultNotAllowedSingleIdpDoesNotSupportPassword() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("oidcprovider"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInfo);
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(false);
        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, localIdp));
        when(identityProviderProvisioning.retrieveByOrigin("oidcprovider", "uaa")).thenReturn(localIdp);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (BadCredentialsException e) {
            assertThat(e.getMessage()).isEqualTo("The client is not authorized for any identity provider that supports password grant.");
        }
    }

    @Test
    void oidcPasswordGrantNoLoginHintDefaultNotAllowedSingleIdpUAA() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInfo);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertThat(captor.getValue()).isNotNull();
        assertThat(captor.getValue().getOrigin()).isEqualTo("uaa");
    }

    @Test
    void oidcPasswordGrantNoLoginHintDefaultNotAllowedChainedAuth() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa", "ldap"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInfo);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        verify(zoneAwareAuthzAuthenticationManager, times(0)).setLoginHint(any(), any());
        verify(identityProviderProvisioning, times(1)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(1)).retrieveActive(any());
    }

    @Test
    void oidcPasswordGrantNoLoginHintDefaultNotAllowedMultipleIdpsWithUaa() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider2");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa", "oidcprovider"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInfo);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        ArgumentCaptor<UaaLoginHint> captor = ArgumentCaptor.forClass(UaaLoginHint.class);
        verify(zoneAwareAuthzAuthenticationManager, times(1)).setLoginHint(eq(auth), captor.capture());
        assertThat(captor.getValue()).isNotNull();
        assertThat(captor.getValue().getOrigin()).isEqualTo("uaa");
    }

    @Test
    void oidcPasswordGrantNoLoginHintDefaultNotAllowedMultipleIdpsOnlyOIDC() {
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("oidcprovider3");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("oidcprovider", "oidcprovider2"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInfo);

        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider2");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);

        when(identityProviderProvisioning.retrieveActive("uaa")).thenReturn(Arrays.asList(uaaProvider, ldapProvider, idp, localIdp));

        try {
            instance.authenticate(auth);
            fail("");
        } catch (BadCredentialsException e) {
            assertThat(e.getMessage()).isEqualTo("The client is authorized for multiple identity providers that support password grant and could not determine which identity provider to use.");
        }
    }

    @Test
    void passwordGrantNoLoginHintNoDefaultTriesChainedAuth() {
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(null);

        instance.authenticate(auth);

        verify(zoneAwareAuthzAuthenticationManager, times(1)).authenticate(auth);
        verify(zoneAwareAuthzAuthenticationManager, times(0)).setLoginHint(any(), any());
        verify(identityProviderProvisioning, times(0)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(1)).retrieveActive(any());
    }

    @Test
    void oidcPasswordGrantLoginHintProviderNotAllowed() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider2");
        Authentication auth = mock(Authentication.class);
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);
        Map<String, Object> additionalInfo = Collections.singletonMap(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa", "oidcprovider"));
        when(uaaClient.getAdditionalInformation()).thenReturn(additionalInfo);

        try {
            instance.authenticate(auth);
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("Client is not authorized for specified user's identity provider.");
        }
    }

    @Test
    void oidcPasswordGrant_credentialsMustNotBeNull() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("user", null);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition()
                .setRelyingPartyId("client-id")
                .setRelyingPartySecret("client-secret");
        idp.setConfig(config);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> instance.oidcPasswordGrant(authentication, idp));
    }

    @Test
    void oidcPasswordGrant_credentialsMustBeString() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("user", new Object());
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition()
                .setRelyingPartyId("client-id")
                .setRelyingPartySecret("client-secret");
        idp.setConfig(config);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> instance.oidcPasswordGrant(authentication, idp));
    }

    @Test
    void oidcPasswordGrant_credentialsMustBeStringButNoSecretNeeded() throws MalformedURLException {
        RestTemplate restTemplate = mock(RestTemplate.class);
        ResponseEntity responseEntity = mock(ResponseEntity.class);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("user", "");

        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(restTemplate);
        when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(responseEntity);
        when(responseEntity.hasBody()).thenReturn(true);
        when(responseEntity.getBody()).thenReturn(Map.of("id_token", "dummy"));

        final IdentityProvider<OIDCIdentityProviderDefinition> localIdp = new IdentityProvider<>();
        localIdp.setOriginKey(new AlphanumericRandomValueStringGenerator(8).generate().toLowerCase());
        final OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition()
                .setRelyingPartyId("client-id")
                .setTokenUrl(URI.create("http://localhost:8080/uaa/oauth/token").toURL());
        config.setAuthMethod("none");
        final OIDCIdentityProviderDefinition spyConfig = spy(config);
        localIdp.setConfig(spyConfig);

        assertThat(instance.oidcPasswordGrant(authentication, localIdp)).isNull();
        verify(spyConfig, atLeast(2)).getAuthMethod();
    }

    @Test
    void oidcPasswordGrant_requireAuthenticationStatement() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("user", new Object());

        final IdentityProvider<OIDCIdentityProviderDefinition> localIdp = new IdentityProvider<>();
        localIdp.setOriginKey(new AlphanumericRandomValueStringGenerator(8).generate().toLowerCase());
        final OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition()
                .setRelyingPartyId("client-id");
        localIdp.setConfig(config);

        assertThatThrownBy(() -> instance.oidcPasswordGrant(authentication, localIdp))
                .isInstanceOf(ProviderConfigurationException.class)
                .hasMessage("External OpenID Connect provider configuration is missing relyingPartySecret, jwtClientAuthentication or authMethod.");
    }

    private void mockKeyInfoService() throws JOSEException {
        KeyInfoService keyInfoService = mock(KeyInfoService.class);
        KeyInfo keyInfo = mock(KeyInfo.class);
        JWSSigner signer = mock(JWSSigner.class);
        when(externalOAuthAuthenticationManager.getKeyInfoService()).thenReturn(keyInfoService);
        when(keyInfoService.getActiveKey()).thenReturn(keyInfo);
        when(keyInfoService.getKey("id")).thenReturn(keyInfo);
        when(keyInfo.algorithm()).thenReturn("RS256");
        when(keyInfo.getSigner()).thenReturn(signer);
        when(keyInfo.verifierCertificate()).thenReturn(Optional.of(X509CertUtils.parse(JwtHelperX5tTest.CERTIFICATE_1)));
        when(keyInfo.keyId()).thenReturn("id");
        when(signer.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.RS256));
        when(signer.sign(any(), any())).thenReturn(new Base64URL("dummy"));
    }

    private Authentication getAuthenticationWithUaaHint() {
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        when(zoneAwareAuthzAuthenticationManager.extractLoginHint(auth)).thenReturn(loginHint);
        return auth;
    }

    private RestTemplate getRestTemplate() {
        RestTemplate rt = mock(RestTemplate.class);
        when(restTemplateConfig.nonTrustingRestTemplate()).thenReturn(rt);
        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);
        return rt;
    }
}
