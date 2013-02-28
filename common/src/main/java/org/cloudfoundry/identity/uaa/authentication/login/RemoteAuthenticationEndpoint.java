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

package org.cloudfoundry.identity.uaa.authentication.login;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

/**
 * A username/password authentication endpoint (only intended) for use by the login server.
 *
 * @author Luke Taylor
 */
@Controller
public class RemoteAuthenticationEndpoint {
	private final Log logger = LogFactory.getLog(getClass());

	private AuthenticationManager authenticationManager;

	public RemoteAuthenticationEndpoint(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@RequestMapping(value = { "/authenticate" }, method = RequestMethod.POST)
	@ResponseBody
	public HttpEntity<Map<String,String>> authenticate(HttpServletRequest request, @RequestParam("username") String username,
			@RequestParam("password") String password) {
		Map<String,String> responseBody = new HashMap<String,String>();

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		token.setDetails(new UaaAuthenticationDetails(request));

		HttpStatus status = HttpStatus.UNAUTHORIZED;
		try {
			Authentication a = authenticationManager.authenticate(token);
			responseBody.put("username", a.getName());
			status = HttpStatus.OK;
		} catch (AuthenticationException e) {
			responseBody.put("error", "authentication failed");
		} catch (Exception e) {
			logger.info("Failed to authenticate user ", e);
			status = HttpStatus.INTERNAL_SERVER_ERROR;
		}

		return new ResponseEntity<Map<String,String>>(responseBody, status);
	}
}
