/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.rest.SimpleMessage;
import org.cloudfoundry.identity.uaa.scim.core.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.users.ScimUser;
import org.cloudfoundry.identity.uaa.scim.users.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller for listing and manipulating access tokens.
 * 
 * @author Dave Syer
 */
@Controller
public class TokenAdminEndpoints {

	private ConsumerTokenServices tokenServices;

	private ScimUserProvisioning scimProvisioning;

	private PasswordEncoder encoder = new StandardPasswordEncoder();

	@RequestMapping("/oauth/users/{user}/tokens")
	@ResponseBody
	public Collection<OAuth2AccessToken> listTokensForUser(@PathVariable String user, Principal principal,
			@RequestParam(required = false, defaultValue = "true") boolean lookup) throws Exception {
		String username = lookup ? getUserName(user) : user;
		checkResourceOwner(username, principal);
		return enhance(tokenServices.findTokensByUserName(username));
	}

	@RequestMapping(value = "/oauth/users/{user}/tokens/{token}", method = RequestMethod.DELETE)
	@ResponseBody
	public SimpleMessage revokeUserToken(@PathVariable String user, @PathVariable String token, Principal principal,
			@RequestParam(required = false, defaultValue = "true") boolean lookup) throws Exception {
		String username = lookup ? getUserName(user) : user;
		checkResourceOwner(username, principal);
		String tokenValue = getTokenValue(tokenServices.findTokensByUserName(username), token);
		if (tokenValue != null && tokenServices.revokeToken(tokenValue)) {
			return new SimpleMessage("ok", "user token revoked");
		}
		throw new NoSuchTokenException("Token not found");
	}

	@RequestMapping("/oauth/clients/{client}/tokens")
	@ResponseBody
	public Collection<OAuth2AccessToken> listTokensForClient(@PathVariable String client, Principal principal)
			throws Exception {
		checkClient(client, principal);
		return enhance(tokenServices.findTokensByClientId(client));
	}

	@RequestMapping(value = "/oauth/clients/{client}/tokens/{token}", method = RequestMethod.DELETE)
	@ResponseBody
	public SimpleMessage revokeClientToken(@PathVariable String client, @PathVariable String token, Principal principal)
			throws Exception {
		checkClient(client, principal);
		String tokenValue = getTokenValue(tokenServices.findTokensByClientId(client), token);
		if (tokenValue != null && tokenServices.revokeToken(tokenValue)) {
			return new SimpleMessage("ok", "client token revoked");
		}
		throw new NoSuchTokenException("Token not found");
	}

	@ExceptionHandler(NoSuchTokenException.class)
	public ResponseEntity<Void> handleNoSuchToken(NoSuchTokenException e) {
		return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
	}

	private String getUserName(String user) {
		if (scimProvisioning == null) {
			return user;
		}
		String username = user;
		try {
			if (scimProvisioning != null) {
				// If the request came in for a user by id we should be able to retrieve the username
				ScimUser scimUser = scimProvisioning.retrieveUser(username);
				if (scimUser != null) {
					username = scimUser.getUserName();
				}
			}
		}
		catch (ScimResourceNotFoundException e) {
			// ignore
		}
		return username;
	}

	private String getTokenValue(Collection<OAuth2AccessToken> tokens, String hash) {
		for (OAuth2AccessToken token : tokens) {
			try {
				if (token.getAdditionalInformation().containsKey(JwtTokenEnhancer.TOKEN_ID)
						&& hash.equals(token.getAdditionalInformation().get(JwtTokenEnhancer.TOKEN_ID))
						|| encoder.matches(token.getValue(), hash)) {
					return token.getValue();
				}
			}
			catch (Exception e) {
				// it doesn't match
			}
		}
		return null;
	}

	private Collection<OAuth2AccessToken> enhance(Collection<OAuth2AccessToken> tokens) {
		Collection<OAuth2AccessToken> result = new ArrayList<OAuth2AccessToken>();
		for (OAuth2AccessToken prototype : tokens) {
			DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(prototype);
			Map<String, Object> map = new HashMap<String, Object>(token.getAdditionalInformation());
			if (!map.containsKey(JwtTokenEnhancer.TOKEN_ID)) {
				// The token doesn't have an ID in the token service, but we need one for the endpoint, so add one here
				map.put(JwtTokenEnhancer.TOKEN_ID, encoder.encode(token.getValue()));
			}
			try {
				String clientId = tokenServices.getClientId(token.getValue());
				if (clientId != null) {
					map.put("client_id", clientId);
				}
			}
			catch (InvalidTokenException e) {
				// Ignore defensively in case of bugs in token services
			}
			token.setAdditionalInformation(map);
			result.add(token);
		}
		return result;
	}

	private void checkResourceOwner(String user, Principal principal) {
		if (principal instanceof OAuth2Authentication) {
			OAuth2Authentication authentication = (OAuth2Authentication) principal;
			if (!authentication.isClientOnly() && !user.equals(principal.getName())) {
				throw new AccessDeniedException(String.format("User '%s' cannot obtain tokens for user '%s'",
						principal.getName(), user));
			}
		}
		else if (!user.equals(principal.getName())) {
			throw new AccessDeniedException(String.format("User '%s' cannot obtain tokens for user '%s'",
					principal.getName(), user));
		}

	}

	private void checkClient(String client, Principal principal) {
		if (principal instanceof OAuth2Authentication) {
			OAuth2Authentication authentication = (OAuth2Authentication) principal;
			if (!authentication.isClientOnly() || !client.equals(principal.getName()) && !isAdmin(principal)) {
				throw new AccessDeniedException(String.format("Client '%s' cannot obtain tokens for client '%s'",
						principal.getName(), client));
			}
		}
	}

	private boolean isAdmin(Principal principal) {
		return AuthorityUtils.authorityListToSet(((Authentication) principal).getAuthorities()).contains(
				UaaAuthority.UAA_ADMIN.toString());
	}

	/**
	 * @param tokenServices the consumerTokenServices to set
	 */
	public void setTokenServices(ConsumerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	/**
	 * @param scimProvisioning the scimProvisioning to set
	 */
	public void setScimUserProvisioning(ScimUserProvisioning scimProvisioning) {
		this.scimProvisioning = scimProvisioning;
	}

}
