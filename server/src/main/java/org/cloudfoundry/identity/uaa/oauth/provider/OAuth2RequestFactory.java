package org.cloudfoundry.identity.uaa.oauth.provider;

import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface OAuth2RequestFactory {

    /**
     * Create a new {@link AuthorizationRequest} extracting all the needed information from the incoming parameter map,
     * and initializing all individual fields on the {@link AuthorizationRequest} to reasonable values. When a class
     * uses the factory to create an {@link AuthorizationRequest}, it should not need to access the parameter map
     * directly afterwards.
     * 
     * Typical implementations would initialize the individual fields on the {@link AuthorizationRequest} with the
     * values requested in the original parameter map. It may also load the client details from the client id provided
     * and validate the grant type and scopes, populating any fields in the request that are known only to the
     * authorization server.
     * 
     * @param authorizationParameters the parameters in the request
     * @return a new AuthorizationRequest
     */
    AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters);

    /**
     * Create a new {@link OAuth2Request} by extracting the needed information from the current
     * {@link AuthorizationRequest} object.
     * 
     * @param request the request to be converted
     * @return an immutable object for storage
     */
    OAuth2Request createOAuth2Request(AuthorizationRequest request);

    /**
     * Create a new {@link OAuth2Request} by extracting the needed information from the current {@link TokenRequest}
     * object.
     * @param client
     * @param tokenRequest the request to be converted
     * 
     * @return am immutable object for storage
     */
    OAuth2Request createOAuth2Request(ClientDetails client, TokenRequest tokenRequest);

    /**
     * Create a new {@link TokenRequest} by extracting the needed information from the incoming request parameter map.
     * 
     * @param requestParameters the parameters in the request
     * @param authenticatedClient the client that authenticated during the token request
     * @return a new TokenRequest
     */
    TokenRequest createTokenRequest(Map<String, String> requestParameters, ClientDetails authenticatedClient);

    /**
     * Create a new {@link TokenRequest} from an {@link AuthorizationRequest}. Principally used by the
     * AuthorizationEndpoint during the implicit flow.
     * 
     * @param authorizationRequest the incoming request
     * @param grantType the grant type for the token request
     * @return a new token request
     */
    TokenRequest createTokenRequest(AuthorizationRequest authorizationRequest, String grantType);

}