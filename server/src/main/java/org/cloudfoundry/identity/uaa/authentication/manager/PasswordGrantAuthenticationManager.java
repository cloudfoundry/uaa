package org.cloudfoundry.identity.uaa.authentication.manager;

import org.apache.commons.lang3.ObjectUtils;
import org.cloudfoundry.identity.uaa.authentication.AbstractClientParametersAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.*;
import java.util.function.Supplier;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.util.StringUtils.hasText;

public class PasswordGrantAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

    private DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private RestTemplateConfig restTemplateConfig;
    private ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private ApplicationEventPublisher eventPublisher;

    public PasswordGrantAuthenticationManager(DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager, final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning identityProviderProvisioning, RestTemplateConfig restTemplateConfig, ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager) {
        this.zoneAwareAuthzAuthenticationManager = zoneAwareAuthzAuthenticationManager;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.restTemplateConfig = restTemplateConfig;
        this.externalOAuthAuthenticationManager = externalOAuthAuthenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UaaLoginHint uaaLoginHint = zoneAwareAuthzAuthenticationManager.extractLoginHint(authentication);
        List<String> allowedProviders = getAllowedProviders();
        String defaultProvider = IdentityZoneHolder.get().getConfig().getDefaultIdentityProvider();
        UaaLoginHint loginHintToUse;
        IdentityProvider<?> identityProvider = retrievePasswordIdp(uaaLoginHint, defaultProvider, allowedProviders);
        List<String> possibleProviders;
        if (identityProvider != null) {
            possibleProviders = List.of(identityProvider.getOriginKey());
        } else {
            List<String> identityProviders = identityProviderProvisioning.retrieveActive(IdentityZoneHolder.get().getId()).stream().filter(this::providerSupportsPasswordGrant).map(IdentityProvider::getOriginKey).toList();
            possibleProviders = Optional.ofNullable(allowedProviders).orElse(identityProviders).stream().filter(identityProviders::contains).toList();
        }
        if (uaaLoginHint == null) {
            if (defaultProvider != null && possibleProviders.contains(defaultProvider)) {
                loginHintToUse = new UaaLoginHint(defaultProvider);
            } else {
                loginHintToUse = getUaaLoginHintForChainedAuth(possibleProviders);
                if (identityProvider == null) {
                    identityProvider = retrievePasswordIdp(loginHintToUse, null, null);
                }
            }
        } else {
            if (possibleProviders.contains(uaaLoginHint.getOrigin())) {
                loginHintToUse = uaaLoginHint;
            } else if (allowedProviders == null || allowedProviders.contains(uaaLoginHint.getOrigin())){
                throw new ProviderConfigurationException("The origin provided in the login_hint does not match an active Identity Provider, that supports password grant.");
            } else {
                throw new ProviderConfigurationException("Client is not authorized for specified user's identity provider.");
            }
        }
        if (loginHintToUse != null) {
            zoneAwareAuthzAuthenticationManager.setLoginHint(authentication, loginHintToUse);
        }
        if (identityProvider == null || loginHintToUse == null || loginHintToUse.getOrigin() == null || loginHintToUse.getOrigin().equals(OriginKeys.UAA) || loginHintToUse.getOrigin().equals(OriginKeys.LDAP)) {
            return zoneAwareAuthzAuthenticationManager.authenticate(authentication);
        } else {
            if (OriginKeys.OIDC10.equals(identityProvider.getType()) && identityProvider.getConfig() instanceof OIDCIdentityProviderDefinition) {
                return oidcPasswordGrant(authentication, (IdentityProvider<OIDCIdentityProviderDefinition>) identityProvider);
            }
        }
        throw new ProviderConfigurationException("Invalid identity provider type");
    }

    private IdentityProvider<?> retrievePasswordIdp(UaaLoginHint loginHint, String defaultOrigin, List<String> allowedProviders) {
        String useOrigin = loginHint != null && loginHint.getOrigin() != null ? loginHint.getOrigin() : defaultOrigin;
        if (useOrigin != null) {
            try {
                IdentityProvider<?> retrievedByOrigin = identityProviderProvisioning.retrieveByOrigin(useOrigin,
                    IdentityZoneHolder.get().getId());
                if (retrievedByOrigin != null && retrievedByOrigin.isActive() && retrievedByOrigin.getOriginKey().equals(useOrigin)
                    && providerSupportsPasswordGrant(retrievedByOrigin) && (allowedProviders == null || allowedProviders.contains(useOrigin))) {
                    return retrievedByOrigin;
                }
            } catch (EmptyResultDataAccessException e) {
                // ignore
            }
        }
        return null;
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
        } else if (allowedProviders.size() == 0){
            throw new BadCredentialsException("The client is not authorized for any identity provider that supports password grant.");
        } else {
            throw new BadCredentialsException("The client is authorized for multiple identity providers that support password grant and could not determine which identity provider to use.");
        }
        return loginHintToUse;
    }

    Authentication oidcPasswordGrant(Authentication authentication, final IdentityProvider<OIDCIdentityProviderDefinition> identityProvider) {
        final OIDCIdentityProviderDefinition config = identityProvider.getConfig();

        //Token per RestCall
        URL tokenUrl = config.getTokenUrl();
        String clientId = config.getRelyingPartyId();
        String clientSecret = config.getRelyingPartySecret();
        if (clientId == null) {
            throw new ProviderConfigurationException("External OpenID Connect provider configuration is missing relyingPartyId.");
        }
        if (clientSecret == null && config.getJwtClientAuthentication() == null && config.getAuthMethod() == null) {
            throw new ProviderConfigurationException("External OpenID Connect provider configuration is missing relyingPartySecret, jwtClientAuthentication or authMethod.");
        }
        String calcAuthMethod = ClientAuthentication.getCalculatedMethod(config.getAuthMethod(), clientSecret != null, config.getJwtClientAuthentication() != null);
        String userName = authentication.getPrincipal() instanceof String ? (String)authentication.getPrincipal() : null;
        if (userName == null || authentication.getCredentials() == null || !(authentication.getCredentials() instanceof String)) {
            throw new BadCredentialsException("Request is missing username or password.");
        }
        Supplier<String> passProvider = () -> (String) authentication.getCredentials();
        RestTemplate rt;
        if (config.isSkipSslValidation()) {
            rt = restTemplateConfig.trustingRestTemplate();
        } else {
            rt = restTemplateConfig.nonTrustingRestTemplate();
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

        if (ClientAuthentication.PRIVATE_KEY_JWT.equals(calcAuthMethod)) {
            /* ensure that the dynamic lookup of the cert and/or key for private key JWT works for an alias IdP in a
             * custom IdZ */
            final boolean allowDynamicValueLookupInCustomZone = hasText(identityProvider.getAliasZid()) && hasText(identityProvider.getAliasId());
            params = new JwtClientAuthentication(externalOAuthAuthenticationManager.getKeyInfoService())
                    .getClientAuthenticationParameters(params, config, allowDynamicValueLookupInCustomZone);
        } else if (ClientAuthentication.secretNeeded(calcAuthMethod)){
            String auth = clientId + ":" + clientSecret;
            headers.add("Authorization", "Basic " + Base64Utils.encodeToString(auth.getBytes()));
        } else {
            params.add(AbstractClientParametersAuthenticationFilter.CLIENT_ID, clientId);
        }
        if (config.isSetForwardHeader() && authentication.getDetails() != null &&authentication.getDetails() instanceof UaaAuthenticationDetails) {
            UaaAuthenticationDetails details = (UaaAuthenticationDetails) authentication.getDetails();
            if (details.getOrigin() != null) {
                headers.add("X-Forwarded-For", details.getOrigin());
            }
        }
        params.add("grant_type", GRANT_TYPE_PASSWORD);
        params.add("response_type","id_token");
        params.add("username", userName);
        params.add("password", passProvider.get());
        if (ObjectUtils.isNotEmpty(config.getScopes())) {
            params.add("scope", String.join(" ", config.getScopes()));
        }

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
                if (values == null || values.length != 1 || !hasText(values[0])) {
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
                idToken = body != null ? body.get("id_token") : null;
            }
        } catch (HttpClientErrorException e) {
            publish(new IdentityProviderAuthenticationFailureEvent(authentication, userName, OriginKeys.OIDC10, IdentityZoneHolder.getCurrentZoneId()));
            throw new BadCredentialsException(e.getResponseBodyAsString(), e);
        }

        if (idToken == null) {
            publish(new IdentityProviderAuthenticationFailureEvent(authentication, userName, OriginKeys.OIDC10, IdentityZoneHolder.getCurrentZoneId()));
            throw new BadCredentialsException("Could not obtain id_token from external OpenID Connect provider.");
        }
        ExternalOAuthCodeToken token = new ExternalOAuthCodeToken(null, null, null, idToken, null, null);
        return externalOAuthAuthenticationManager.authenticate(token);
    }

    private boolean providerSupportsPasswordGrant(IdentityProvider provider) {
        if (OriginKeys.UAA.equals(provider.getType()) || OriginKeys.LDAP.equals(provider.getType())) {
            return true;
        }
        if (!OriginKeys.OIDC10.equals(provider.getType()) || !(provider.getConfig() instanceof OIDCIdentityProviderDefinition)) {
            return false;
        }
        OIDCIdentityProviderDefinition config = (OIDCIdentityProviderDefinition) provider.getConfig();
        return config.isPasswordGrantEnabled();
    }


    private List<String> getAllowedProviders() {
        Authentication clientAuth = SecurityContextHolder.getContext().getAuthentication();
        if (clientAuth == null) {
            throw new BadCredentialsException("No client authentication found.");
        }
        List<String> allowedProviders = null;
        if (clientAuth.getPrincipal() instanceof UaaClient uaaClient && uaaClient.getAdditionalInformation() != null) {
            allowedProviders = (List<String>) uaaClient.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);
        }
        return allowedProviders;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }
}
