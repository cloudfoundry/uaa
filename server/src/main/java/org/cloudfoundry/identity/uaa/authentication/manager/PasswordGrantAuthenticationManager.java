package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthCodeToken;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.Arrays;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;

public class PasswordGrantAuthenticationManager implements AuthenticationManager {

    private DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private RestTemplateConfig restTemplateConfig;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;

    public PasswordGrantAuthenticationManager(DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager, IdentityProviderProvisioning identityProviderProvisioning, RestTemplateConfig restTemplateConfig, XOAuthAuthenticationManager xoAuthAuthenticationManager) {
        this.zoneAwareAuthzAuthenticationManager = zoneAwareAuthzAuthenticationManager;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.restTemplateConfig = restTemplateConfig;
        this.xoAuthAuthenticationManager = xoAuthAuthenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UaaLoginHint uaaLoginHint = zoneAwareAuthzAuthenticationManager.extractLoginHint(authentication);
        if (uaaLoginHint == null || uaaLoginHint.getOrigin() == null || uaaLoginHint.getOrigin().equals(OriginKeys.UAA) || uaaLoginHint.getOrigin().equals(OriginKeys.LDAP)) {
            return zoneAwareAuthzAuthenticationManager.authenticate(authentication);
        } else {
            return oidcPasswordGrant(authentication, uaaLoginHint);
        }
    }

    private Authentication oidcPasswordGrant(Authentication authentication, UaaLoginHint uaaLoginHint) {
        //Get IDP
        IdentityProvider idp = null;
        try {
            idp = identityProviderProvisioning.retrieveByOrigin(uaaLoginHint.getOrigin(), IdentityZoneHolder.get().getId());
        } catch (DataAccessException e) {
            throw new ProviderNotFoundException("The origin provided in the login hint is invalid.");
        }
        if (!idp.isActive() || !OriginKeys.OIDC10.equals(idp.getType()) || !(idp.getConfig() instanceof OIDCIdentityProviderDefinition)) {
            throw new ProviderConfigurationException("The origin provided does not match an active OpenID Connect provider.");
        }
        OIDCIdentityProviderDefinition config = (OIDCIdentityProviderDefinition)idp.getConfig();
        if (!config.isPasswordGrantEnabled()) {
            throw new ProviderConfigurationException("External OpenID Connect provider is not configured for password grant.");
        }
        //Token per RestCall
        URL tokenUrl = config.getTokenUrl();
        String clientId = config.getRelyingPartyId();
        String clientSecret = config.getRelyingPartySecret();
        if (clientId == null || clientSecret == null) {
            throw new ProviderConfigurationException("External OpenID Connect provider configuration is missing relyingPartyId or relyingPartySecret.");
        }
        String userName = authentication.getPrincipal() instanceof String ? (String)authentication.getPrincipal() : null;
        String password = authentication.getCredentials() instanceof String ? (String)authentication.getCredentials() : null;
        if (userName == null || password == null) {
            throw new BadCredentialsException("Request is missing username or password.");
        }
        RestTemplate rt;
        if (config.isSkipSslValidation()) {
            rt = restTemplateConfig.trustingRestTemplate();
        } else {
            rt = restTemplateConfig.nonTrustingRestTemplate();
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        String auth = clientId + ":" + clientSecret;
        headers.add("Authorization","Basic "+Base64Utils.encodeToString(auth.getBytes()));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("response_type","id_token");
        params.add("username", userName);
        params.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        String idToken = null;
        try {
            ResponseEntity<Map<String,String>> tokenResponse = rt.exchange(tokenUrl.toString(), HttpMethod.POST, request, new ParameterizedTypeReference<Map<String,String>>(){});

            if (tokenResponse.hasBody()) {
                Map<String, String> body = tokenResponse.getBody();
                idToken = body.get("id_token");
            }
        } catch (HttpClientErrorException e) {
            throw new BadCredentialsException(e.getResponseBodyAsString(), e);
        }

        if (idToken == null) {
            throw new BadCredentialsException("Could not obtain id_token from external OpenID Connect provider.");
        }
        XOAuthCodeToken token = new XOAuthCodeToken(null, null, null, idToken, null, null);
        Authentication authResult = xoAuthAuthenticationManager.authenticate(token);
        return authResult;
    }
}
