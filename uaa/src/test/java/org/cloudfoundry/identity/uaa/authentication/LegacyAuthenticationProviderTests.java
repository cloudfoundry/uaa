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
package org.cloudfoundry.identity.uaa.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.remoting.support.SimpleHttpServerFactoryBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * @author Dave Syer
 *
 */
@SuppressWarnings("restriction")
public class LegacyAuthenticationProviderTests {
	
	private LegacyAuthenticationProvider authenticationProvider = new LegacyAuthenticationProvider();
	private static SimpleHttpServerFactoryBean factory;
	
	@BeforeClass
	public static void setup() throws Exception {
		factory = new SimpleHttpServerFactoryBean();
		factory.setPort(8888);
		factory.setContexts(Collections.singletonMap("/token", (HttpHandler) new HttpHandler() {
			@Override
			public void handle(HttpExchange exchange) throws IOException {
				exchange.getResponseHeaders().set("Content-Type", "application/json");
				exchange.sendResponseHeaders(200, 0);
				OutputStream stream = exchange.getResponseBody();
				stream.write("{\"token\":\"FOO\"}".getBytes());
				stream.flush();
			}		
		}));
		factory.afterPropertiesSet();
	}
	
	@AfterClass
	public static void close() throws Exception {
		factory.destroy();
	}

	@Test
	public void testAuthenticate() {
		authenticationProvider.setCloudControllerUrl("http://localhost:8888/token");
		Authentication result = authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken("foo@bar.com", ""));
		assertNotNull(result);
		@SuppressWarnings("unchecked")
		Map<String,String> details = (Map<String,String>)result.getDetails();
		assertEquals("FOO", details.get("token"));
	}
	
	@Test
	public void testBuildDetails() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("email", "foo@bar.com");
		request.addParameter("password", "secret");
		Map<String, String> details = authenticationProvider.buildDetails(request);
		assertNotNull(details);
		assertEquals("foo@bar.com", details.get("email"));
	}
	
	@Test
	public void testSupports() throws Exception {
		assertTrue(authenticationProvider.supports(UsernamePasswordAuthenticationToken.class));
		assertFalse(authenticationProvider.supports(UaaAuthentication.class));
	}

}
