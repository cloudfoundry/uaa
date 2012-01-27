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
package org.cloudfoundry.identity.uaa.integration;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.remoting.support.SimpleHttpServerFactoryBean;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * Convenience for setting up a lightweight local HTTP server to provide legacy style (cloud_conttoller) tokens.
 * 
 * @author Dave Syer
 * 
 */
@SuppressWarnings("restriction")
public class LegacyTokenServer {

	private static final Log logger = LogFactory.getLog(LegacyTokenServer.class);

	private RandomValueStringGenerator generator = new RandomValueStringGenerator();

	private SimpleHttpServerFactoryBean factory;

	private final int port;

	private String expectedpassword;

	private String tokenValue;

	public LegacyTokenServer() {
		this(8888, null);
	}

	public LegacyTokenServer(int port) {
		this(port, null);
	}

	public LegacyTokenServer(int port, String expectedpassword) {
		this.port = port;
		this.expectedpassword = expectedpassword;
	}

	/**
	 * @param expectedpassword the expected password to set
	 */
	public void setExpectedpassword(String expectedpassword) {
		this.expectedpassword = expectedpassword;
	}

	/**
	 * The value of teh access token to return on successful authentication. If null the value will be randomly
	 * generated.
	 * 
	 * @param tokenValue the token value to set
	 */
	public void setTokenValue(String tokenValue) {
		this.tokenValue = tokenValue;
	}

	public void init() throws Exception {
		factory = new SimpleHttpServerFactoryBean();
		factory.setPort(port);
		factory.setContexts(Collections.singletonMap("/token", (HttpHandler) new HttpHandler() {
			@Override
			public void handle(HttpExchange exchange) throws IOException {
				InputStream bodyStream = exchange.getRequestBody();
				byte[] bodyBytes = new byte[bodyStream.available()];
				bodyStream.read(bodyBytes);
				bodyStream.close();
				String body = new String(bodyBytes, "UTF-8");
				exchange.getResponseHeaders().set("Content-Type", "application/json");
				int code;
				byte[] content;

				boolean authenticated = false;
				if (expectedpassword != null) {
					authenticated = body.equals("{\"password\":\"" + expectedpassword + "\"}");
				}
				else {
					authenticated = body.contains("{\"password\":\"");
				}
				if (authenticated) {
					code = 200;
					String token = tokenValue!=null ? tokenValue : generator.generate();
					content = String.format("{\"token\":\"%s\"}", token).getBytes("UTF-8");
					logger.debug("Successful authentication with token=" + token);
				}
				else {
					code = 403;
					content = "".getBytes("UTF-8");
					logger.debug("Forbidden");
				}
				exchange.sendResponseHeaders(code, content.length);
				OutputStream stream = exchange.getResponseBody();
				stream.write(content);
				stream.flush();
				exchange.close();
			}
		}));
		factory.afterPropertiesSet();
	}

	public void close() throws Exception {
		factory.destroy();
	}

}
