package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class OAuth2AuthenticationManager implements AuthenticationManager, InitializingBean {

    private ResourceServerTokenServices tokenServices;

    private ClientDetailsService clientDetailsService;

    private String resourceId;

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * @param tokenServices the tokenServices to set
     */
    public void setTokenServices(ResourceServerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    public void afterPropertiesSet() {
        Assert.state(tokenServices != null, "TokenServices are required");
    }

    /**
     * Expects the incoming authentication request to have a principal value that is an access token value (e.g. from an
     * authorization header). Loads an authentication from the {@link ResourceServerTokenServices} and checks that the
     * resource id is contained in the {@link AuthorizationRequest} (if one is specified). Also copies authentication
     * details over from the input to the output (e.g. typically so that the access token value and request details can
     * be reported later).
     * 
     * @param authentication an authentication request containing an access token value as the principal
     * @return an {@link OAuth2Authentication}
     * 
     * @see AuthenticationManager#authenticate(Authentication)
     */
    public Authentication authenticate(Authentication inAuth) throws AuthenticationException {

        Authentication authentication = Optional.ofNullable(inAuth).orElseThrow(() -> new InvalidTokenException("Invalid token (token not found)"));
        String token = (String) authentication.getPrincipal();
        OAuth2Authentication auth = Optional.ofNullable(tokenServices.loadAuthentication(token)).orElseThrow(() -> new InvalidTokenException("Invalid token"));

        Collection<String> resourceIds = auth.getOAuth2Request().getResourceIds();
        if (resourceId != null && resourceIds != null && !resourceIds.isEmpty() && !resourceIds.contains(resourceId)) {
            throw new OAuth2AccessDeniedException("Invalid token does not contain resource id (" + resourceId + ")");
        }

        checkClientDetails(auth);

        if (authentication.getDetails() instanceof OAuth2AuthenticationDetails details && !details.equals(auth.getDetails())) {
            // Guard against a cached copy of the same details
            // Preserve the authentication details from the one loaded by token services
            details.setDecodedDetails(auth.getDetails());
        }
        auth.setDetails(authentication.getDetails());
        auth.setAuthenticated(true);
        return auth;

    }

    private void checkClientDetails(OAuth2Authentication auth) {
        if (clientDetailsService != null) {
            ClientDetails client;
            try {
                client = clientDetailsService.loadClientByClientId(auth.getOAuth2Request().getClientId());
            }
            catch (ClientRegistrationException e) {
                throw new OAuth2AccessDeniedException("Invalid token contains invalid client id");
            }
            Set<String> allowed = client.getScope();
            for (String scope : auth.getOAuth2Request().getScope()) {
                if (!allowed.contains(scope)) {
                    throw new OAuth2AccessDeniedException(
                            "Invalid token contains disallowed scope for this client");
                }
            }
        }
    }

}
