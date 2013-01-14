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
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
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
	public Map<String,String> authenticate(HttpServletRequest request, HttpServletResponse response) {
		String username = request.getParameter("username");
		String password =  request.getParameter("password");

		Map<String,String> responseBody = new HashMap<String,String>();

		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
			responseBody.put("error", "username and password are required");
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			return responseBody;
		}

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		token.setDetails(new UaaAuthenticationDetails(request));

		try {
			Authentication a = authenticationManager.authenticate(token);
			responseBody.put("username", a.getName());
		} catch (AuthenticationException e) {
			responseBody.put("error", "authentication failed");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		} catch (Exception e) {
			logger.info("Failed to authenticate user ", e);
			response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}

		return responseBody;
	}
}
