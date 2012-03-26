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
package org.cloudfoundry.identity.uaa.error;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * If authentication fails and the caller has asked for a JSON response this can send one, along with a standard 401
 * status.
 * 
 * @author Dave Syer
 * 
 */
public class JsonAwareAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

	private String realmName;

	private String typeName = "Basic";

	public void afterPropertiesSet() throws Exception {
		Assert.state(StringUtils.hasText(realmName), "realmName must be specified");
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
			throws IOException, ServletException {
		response.addHeader("WWW-Authenticate", String.format("%s realm=\"%s\"", typeName, realmName));
		String accept = request.getHeader("Accept");
		boolean json = false;
		if (StringUtils.hasText(accept)) {
			for (MediaType mediaType : MediaType.parseMediaTypes(accept)) {
				if (mediaType.includes(MediaType.APPLICATION_JSON)) {
					json = true;
					break;
				}
			}
		}
		if (json) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.getWriter().append(String.format("{\"error\":\"%s\"}", authException.getMessage()));
		} else {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());			
		}
	}

	public void setRealmName(String realmName) {
		this.realmName = realmName;
	}

	public void setTypeName(String typeName) {
		this.typeName = typeName;
	}
}
