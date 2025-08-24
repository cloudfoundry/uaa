package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
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
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;

public class PasswordGrantAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

    private final DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private ApplicationEventPublisher eventPublisher;

    public PasswordGrantAuthenticationManager(DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager, final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning identityProviderProvisioning, ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager) {
        this.zoneAwareAuthzAuthenticationManager = zoneAwareAuthzAuthenticationManager;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.externalOAuthAuthenticationManager = externalOAuthAuthenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UaaLoginHint uaaLoginHint = zoneAwareAuthzAuthenticationManager.extractLoginHint(authentication);
        List<String> allowedProviders = externalOAuthAuthenticationManager.getAllowedProviders();
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
            } else if (allowedProviders == null || allowedProviders.contains(uaaLoginHint.getOrigin())) {
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
                IdentityProvider<?> retrievedByOrigin = identityProviderProvisioning.retrieveByOrigin(useOrigin, IdentityZoneHolder.get().getId());
                if (retrievedByOrigin != null && retrievedByOrigin.isActive() && retrievedByOrigin.getOriginKey().equals(useOrigin)
                        && providerSupportsPasswordGrant(retrievedByOrigin)
                        && (allowedProviders == null || allowedProviders.contains(useOrigin))) {
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
            loginHintToUse = new UaaLoginHint(allowedProviders.getFirst());
        } else if (allowedProviders.contains(OriginKeys.UAA)) {
            if (!allowedProviders.contains(OriginKeys.LDAP)) {
                loginHintToUse = new UaaLoginHint(OriginKeys.UAA);
            }
        } else if (allowedProviders.contains(OriginKeys.LDAP)) {
            loginHintToUse = new UaaLoginHint(OriginKeys.LDAP);
        } else if (allowedProviders.isEmpty()) {
            throw new BadCredentialsException("The client is not authorized for any identity provider that supports password grant.");
        } else {
            throw new BadCredentialsException("The client is authorized for multiple identity providers that support password grant and could not determine which identity provider to use.");
        }
        return loginHintToUse;
    }

    Authentication oidcPasswordGrant(Authentication authentication, final IdentityProvider<OIDCIdentityProviderDefinition> identityProvider) {
        UaaAuthenticationDetails uaaAuthenticationDetails = null;
        if (authentication.getDetails() instanceof UaaAuthenticationDetails details) {
            uaaAuthenticationDetails = details;
        }
        String userName = authentication.getPrincipal() instanceof String pStr ? pStr : null;
        if (userName == null || authentication.getCredentials() == null || !(authentication.getCredentials() instanceof String)) {
            throw new BadCredentialsException("Request is missing username or password.");
        }
        Supplier<String> passProvider = () -> (String) authentication.getCredentials();
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("username", userName);
        params.add("password", passProvider.get());
        String idToken;
        try {
            idToken = externalOAuthAuthenticationManager.oauthTokenRequest(uaaAuthenticationDetails, identityProvider, GRANT_TYPE_PASSWORD, params);
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
