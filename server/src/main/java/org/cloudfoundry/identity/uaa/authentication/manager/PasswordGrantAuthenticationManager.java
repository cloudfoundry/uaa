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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;

public class PasswordGrantAuthenticationManager implements AuthenticationManager {

    private DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private RestTemplateConfig restTemplateConfig;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;
    private ClientServicesExtension clientDetailsService;

    public PasswordGrantAuthenticationManager(DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager, IdentityProviderProvisioning identityProviderProvisioning, RestTemplateConfig restTemplateConfig, XOAuthAuthenticationManager xoAuthAuthenticationManager, ClientServicesExtension clientDetailsService) {
        this.zoneAwareAuthzAuthenticationManager = zoneAwareAuthzAuthenticationManager;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.restTemplateConfig = restTemplateConfig;
        this.xoAuthAuthenticationManager = xoAuthAuthenticationManager;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UaaLoginHint uaaLoginHint = zoneAwareAuthzAuthenticationManager.extractLoginHint(authentication);
        List<String> allowedProviders = getAllowedProviders();
        String defaultProvider = IdentityZoneHolder.get().getConfig().getDefaultIdentityProvider();
        UaaLoginHint loginHintToUse = null;
        if (uaaLoginHint == null) {
            if (defaultProvider == null) {
                if (allowedProviders != null) {
                    loginHintToUse = getUaaLoginHintForChainedAuth(allowedProviders);
                }
            } else {
                if (allowedProviders == null || allowedProviders.contains(defaultProvider)) {
                    loginHintToUse = new UaaLoginHint(defaultProvider);
                } else {
                    loginHintToUse = getUaaLoginHintForChainedAuth(allowedProviders);
                }
            }
        } else {
            loginHintToUse = uaaLoginHint;
        }
        if (loginHintToUse != null) {
            zoneAwareAuthzAuthenticationManager.setLoginHint(authentication, loginHintToUse);
        }
        if (loginHintToUse == null || loginHintToUse.getOrigin() == null || loginHintToUse.getOrigin().equals(OriginKeys.UAA) || loginHintToUse.getOrigin().equals(OriginKeys.LDAP)) {
            return zoneAwareAuthzAuthenticationManager.authenticate(authentication);
        } else {
            return oidcPasswordGrant(authentication, getOidcIdentityProviderDefinitionForPasswordGrant(loginHintToUse));
        }
    }

    private UaaLoginHint getUaaLoginHintForChainedAuth(List<String> allowedProviders) {
        UaaLoginHint loginHintToUse = null;
        if (allowedProviders.size() == 1) {
            loginHintToUse = new UaaLoginHint(allowedProviders.get(0));
        } else if (allowedProviders.contains(OriginKeys.UAA)) {
            if (!allowedProviders.contains(OriginKeys.LDAP)) {
                loginHintToUse = new UaaLoginHint(OriginKeys.UAA);
            }
        } else if (allowedProviders.contains(OriginKeys.LDAP)) {
            loginHintToUse = new UaaLoginHint(OriginKeys.LDAP);
        } else {
            throw new BadCredentialsException("Multiple allowed identity providers were found. No single identity provider could be selected.");
        }
        return loginHintToUse;
    }

    private Authentication oidcPasswordGrant(Authentication authentication, OIDCIdentityProviderDefinition config) {
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

        List<Prompt> prompts = config.getPrompts();
        List<String> promptsToInclude = new ArrayList<>();
        if (prompts != null) {
            for (Prompt prompt : prompts) {
                if ("username".equals(prompt.getName()) || "password".equals(prompt.getName()) || "passcode".equals(prompt.getName()))
                    continue;
                promptsToInclude.add(prompt.getName());
            }
        }
        if (authentication.getDetails() instanceof UaaAuthenticationDetails) {
            UaaAuthenticationDetails details = (UaaAuthenticationDetails)authentication.getDetails();
            for (String prompt : promptsToInclude) {
                String[] values = details.getParameterMap().get(prompt);
                if (values == null || values.length != 1 || !StringUtils.hasText(values[0])) {
                    continue; //No single value given, skip this parameter
                }
                params.add(prompt, values[0]);
            }
        }



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

    private OIDCIdentityProviderDefinition getOidcIdentityProviderDefinitionForPasswordGrant(UaaLoginHint uaaLoginHint) {
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
        return config;
    }


    private List<String> getAllowedProviders() {
        Authentication clientAuth = SecurityContextHolder.getContext().getAuthentication();
        if (clientAuth == null) {
            throw new BadCredentialsException("No client authentication found.");
        }
        String clientId = clientAuth.getName();
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        List<String> allowedProviders = (List<String>)clientDetails.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);
        return allowedProviders;
    }
}
