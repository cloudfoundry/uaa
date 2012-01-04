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

import org.springframework.remoting.support.SimpleHttpServerFactoryBean;

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
	private SimpleHttpServerFactoryBean factory;
	private int port;

	public LegacyTokenServer() {
		this(8888);
	}

	public LegacyTokenServer(int port) {
		this.port = port;
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

				if (body.contains("{\"password\":\"password\"}")) {
					code = 200;
					content = "{\"token\":\"FOO\"}".getBytes("UTF-8");
				} else {
					code = 403;
					content = "{\"token\":\"FOO\"}".getBytes("UTF-8");
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
