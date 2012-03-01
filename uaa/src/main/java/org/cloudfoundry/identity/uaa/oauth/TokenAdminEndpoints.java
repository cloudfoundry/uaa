/**
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

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller for listing and manipulating access tokens.
 * 
 * @author Dave Syer
 */
@Controller
public class TokenAdminEndpoints {

	private ConsumerTokenServices tokenServices;

	private PasswordEncoder encoder = new StandardPasswordEncoder();

	@RequestMapping("/oauth/users/{user}/tokens")
	@ResponseBody
	public Collection<OAuth2AccessToken> listTokensForUser(@PathVariable String user, Principal principal)
			throws Exception {
		checkResourceOwner(user, principal);
		return enhance(tokenServices.findTokensByUserName(user));
	}

	@RequestMapping(value = "/oauth/users/{user}/tokens/{token}", method = RequestMethod.DELETE)
	public ResponseEntity<Void> revokeUserToken(@PathVariable String user, @PathVariable String token,
			Principal principal) throws Exception {
		checkResourceOwner(user, principal);
		String tokenValue = getTokenValue(tokenServices.findTokensByUserName(user), token);
		if (tokenValue!=null && tokenServices.revokeToken(tokenValue)) {
			return new ResponseEntity<Void>(HttpStatus.NO_CONTENT);
		}
		else {
			return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
		}
	}

	@RequestMapping("/oauth/clients/{client}/tokens")
	@ResponseBody
	public Collection<OAuth2AccessToken> listTokensForClient(@PathVariable String client, Principal principal)
			throws Exception {
		checkClient(client, principal);
		return enhance(tokenServices.findTokensByClientId(client));
	}

	@RequestMapping(value = "/oauth/clients/{client}/tokens/{token}", method = RequestMethod.DELETE)
	public ResponseEntity<Void> revokeClientToken(@PathVariable String client, @PathVariable String token,
			Principal principal) throws Exception {
		checkClient(client, principal);
		String tokenValue = getTokenValue(tokenServices.findTokensByClientId(client), token);
		if (tokenValue!=null && tokenServices.revokeToken(tokenValue)) {
			return new ResponseEntity<Void>(HttpStatus.NO_CONTENT);
		}
		else {
			return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
		}
	}

	private String getTokenValue(Collection<OAuth2AccessToken> tokens, String hash) {
		try {
			for (OAuth2AccessToken token : tokens) {
				if (encoder.matches(token.getValue(), hash)) {
					return token.getValue();
				}
			}
		}
		catch (Exception e) {
			// it doesn't match
		}
		return null;
	}

	private Collection<OAuth2AccessToken> enhance(Collection<OAuth2AccessToken> tokens) {
		Collection<OAuth2AccessToken> result = new ArrayList<OAuth2AccessToken>();
		for (OAuth2AccessToken token : tokens) {
			Map<String, Object> map = new HashMap<String, Object>(token.getAdditionalInformation());
			map.put("token_id", encoder.encode(token.getValue()));
			String clientId = tokenServices.getClientId(token.getValue());
			if (clientId != null) {
				map.put("client_id", clientId);
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
		} else if (!user.equals(principal.getName())) {
			throw new AccessDeniedException(String.format("User '%s' cannot obtain tokens for user '%s'",
					principal.getName(), user));
		}

	}

	private void checkClient(String client, Principal principal) {
		if (principal instanceof OAuth2Authentication) {
			OAuth2Authentication authentication = (OAuth2Authentication) principal;
			if (!authentication.isClientOnly() || !client.equals(principal.getName())) {
				throw new AccessDeniedException(String.format("Client '%s' cannot obtain tokens for client '%s'",
						principal.getName(), client));
			}
		}
	}

	/**
	 * @param tokenServices the consumerTokenServices to set
	 */
	public void setTokenServices(ConsumerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

}
