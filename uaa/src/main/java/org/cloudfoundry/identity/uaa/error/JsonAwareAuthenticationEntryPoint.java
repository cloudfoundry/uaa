/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
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
