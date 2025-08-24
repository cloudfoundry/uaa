package org.cloudfoundry.identity.uaa.oauth.provider.request;

import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.security.beans.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.springframework.security.core.authority.AuthorityUtils;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class DefaultOAuth2RequestFactory implements OAuth2RequestFactory {

    private final ClientDetailsService clientDetailsService;

    private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

    private boolean checkUserScopes;

    public DefaultOAuth2RequestFactory(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * @param securityContextAccessor the security context accessor to set
     */
    public void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
        this.securityContextAccessor = securityContextAccessor;
    }

    /**
     * Flag to indicate that scopes should be interpreted as valid authorities. No scopes will be granted to a user
     * unless they are permitted as a granted authority to that user.
     *
     * @param checkUserScopes the checkUserScopes to set (default false)
     */
    public void setCheckUserScopes(boolean checkUserScopes) {
        this.checkUserScopes = checkUserScopes;
    }

    public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {

        String clientId = authorizationParameters.get(OAuth2Utils.CLIENT_ID);
        String state = authorizationParameters.get(OAuth2Utils.STATE);
        String redirectUri = authorizationParameters.get(OAuth2Utils.REDIRECT_URI);
        Set<String> responseTypes = OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.RESPONSE_TYPE));

        Set<String> scopes = extractScopes(authorizationParameters, clientId);

        AuthorizationRequest request = new AuthorizationRequest(authorizationParameters, clientId, scopes, null,
                null, false, state, redirectUri, responseTypes);

        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        request.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);

        return request;

    }

    public OAuth2Request createOAuth2Request(AuthorizationRequest request) {
        return request.createOAuth2Request();
    }

    public TokenRequest createTokenRequest(Map<String, String> requestParameters, ClientDetails authenticatedClient) {

        String clientId = requestParameters.get(OAuth2Utils.CLIENT_ID);
        if (clientId == null) {
            // if the clientId wasn't passed in in the map, we add pull it from the authenticated client object
            clientId = authenticatedClient.getClientId();
        } else {
            // otherwise, make sure that they match
            if (!clientId.equals(authenticatedClient.getClientId())) {
                throw new InvalidClientException("Given client ID does not match authenticated client");
            }
        }
        String grantType = requestParameters.get(OAuth2Utils.GRANT_TYPE);

        Set<String> scopes = extractScopes(requestParameters, clientId);
        return new TokenRequest(requestParameters, clientId, scopes, grantType);
    }

    public TokenRequest createTokenRequest(AuthorizationRequest authorizationRequest, String grantType) {
        return new TokenRequest(authorizationRequest.getRequestParameters(), authorizationRequest.getClientId(),
                authorizationRequest.getScope(), grantType);
    }

    public OAuth2Request createOAuth2Request(ClientDetails client, TokenRequest tokenRequest) {
        return tokenRequest.createOAuth2Request(client);
    }

    private Set<String> extractScopes(Map<String, String> requestParameters, String clientId) {
        Set<String> scopes = OAuth2Utils.parseParameterList(requestParameters.get(OAuth2Utils.SCOPE));
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

        if (scopes == null || scopes.isEmpty()) {
            // If no scopes are specified in the incoming data, use the default values registered with the client
            // (the spec allows us to choose between this option and rejecting the request completely, so we'll take the
            // least obnoxious choice as a default).
            scopes = clientDetails.getScope();
        }

        if (checkUserScopes) {
            scopes = checkUserScopes(scopes);
        }
        return scopes;
    }

    private Set<String> checkUserScopes(Set<String> scopes) {
        if (!securityContextAccessor.isUser()) {
            return scopes;
        }
        Set<String> result = new LinkedHashSet<>();
        Set<String> authorities = AuthorityUtils.authorityListToSet(securityContextAccessor.getAuthorities());
        for (String scope : scopes) {
            if (authorities.contains(scope) || authorities.contains(scope.toUpperCase()) || authorities.contains("ROLE_" + scope.toUpperCase())) {
                result.add(scope);
            }
        }
        return result;
    }

}
