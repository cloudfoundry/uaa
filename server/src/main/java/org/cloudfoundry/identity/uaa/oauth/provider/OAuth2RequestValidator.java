package org.cloudfoundry.identity.uaa.oauth.provider;

import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.ClientDetails;

public interface OAuth2RequestValidator {

	/**
	 * Ensure that the client has requested a valid set of scopes.
	 * 
	 * @param authorizationRequest the AuthorizationRequest to be validated
	 * @param client the client that is making the request
	 * @throws InvalidScopeException if a requested scope is invalid
	 */
	public void validateScope(AuthorizationRequest authorizationRequest, ClientDetails client) throws InvalidScopeException;
	
	/**
	 * Ensure that the client has requested a valid set of scopes.
	 * 
	 * @param tokenRequest the TokenRequest to be validated
	 * @param client the client that is making the request
	 * @throws InvalidScopeException if a requested scope is invalid
	 */
	public void validateScope(TokenRequest tokenRequest, ClientDetails client) throws InvalidScopeException;
	
}
