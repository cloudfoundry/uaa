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
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.MethodRule;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriTemplate;
import org.springframework.web.util.UriUtils;

/**
 * <p>
 * A rule that prevents integration tests from failing if the server application is not running or not accessible. If
 * the server is not running in the background all the tests here will simply be skipped because of a violated
 * assumption (showing as successful). Usage:
 * </p>
 * 
 * <pre>
 * &#064;Rule public static ServerRunning brokerIsRunning = ServerRunning.isRunning();
 * 
 * &#064;Test public void testSendAndReceive() throws Exception { // ... test using server etc. }
 * </pre>
 * <p>
 * The rule can be declared as static so that it only has to check once for all tests in the enclosing test case, but
 * there isn't a lot of overhead in making it non-static.
 * </p>
 * 
 * @see Assume
 * @see AssumptionViolatedException
 * 
 * @author Dave Syer
 * 
 */
public class ServerRunning implements MethodRule {

	private static Log logger = LogFactory.getLog(ServerRunning.class);

	// Static so that we only test once on failure: speeds up test suite
	private static Map<Integer, Boolean> serverOnline = new HashMap<Integer, Boolean>();

	// Static so that we only test once on failure
	private static Map<Integer, Boolean> serverOffline = new HashMap<Integer, Boolean>();

	private final boolean assumeOnline;

	private static int DEFAULT_PORT = 8080;

	private static String DEFAULT_HOST = "localhost";

	private static String DEFAULT_ROOT_PATH = "/uaa";

	private int port;

	private String hostName = DEFAULT_HOST;

	private String rootPath = DEFAULT_ROOT_PATH;

	private RestTemplate client;

	private LegacyTokenServer tokenServer;

	/**
	 * @return a new rule that assumes an existing running broker
	 */
	public static ServerRunning isRunning() {
		return new ServerRunning(true);
	}

	/**
	 * @return a new rule that assumes there is no existing broker
	 */
	public static ServerRunning isNotRunning() {
		return new ServerRunning(false);
	}

	private ServerRunning(boolean assumeOnline) {
		this.assumeOnline = assumeOnline;
		setPort(Integer.valueOf(System.getProperty("uaa.port", DEFAULT_PORT + "")));
		setRootPath(System.getProperty("uaa.path", DEFAULT_ROOT_PATH));
		setHostName(System.getProperty("uaa.host", DEFAULT_HOST));
	}

	/**
	 * @param port the port to set
	 */
	public void setPort(int port) {
		this.port = port;
		if (!serverOffline.containsKey(port)) {
			serverOffline.put(port, true);
		}
		if (!serverOnline.containsKey(port)) {
			serverOnline.put(port, true);
		}
		client = getRestTemplate();
	}

	/**
	 * @param hostName the hostName to set
	 */
	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	/**
	 * The context root in the application, e.g. "/uaa" for a local deployment.
	 * 
	 * @param rootPath the rootPath to set
	 */
	public void setRootPath(String rootPath) {
		if (rootPath.equals("/")) {
			rootPath = "";
		}
		else {
			if (!rootPath.startsWith("/")) {
				rootPath = "/" + rootPath;
			}
		}
		this.rootPath = rootPath;
	}

	/**
	 * @return true if the legacy Spring profile is enabled
	 */
	public boolean isLegacy() {
		String profiles = System.getProperty("spring.profiles.active");
		logger.debug("Checking for legacy profile in: [" + profiles + "]");
		return StringUtils.hasText(profiles) && profiles.contains("legacy") && !profiles.contains("!legacy");
	}

	@Override
	public Statement apply(final Statement base, final FrameworkMethod method, final Object target) {

		// Check at the beginning, so this can be used as a static field
		if (assumeOnline) {
			Assume.assumeTrue(serverOnline.get(port));
		}
		else {
			Assume.assumeTrue(serverOffline.get(port));
		}

		RestTemplate client = new RestTemplate();
		boolean online = false;
		try {
			client.getForEntity(new UriTemplate(getUrl("/login")).toString(), String.class);
			online = true;
			logger.info("Basic connectivity test passed");
		}
		catch (RestClientException e) {
			logger.warn(String.format(
					"Not executing tests because basic connectivity test failed for hostName=%s, port=%d", hostName,
					port), e);
			if (assumeOnline) {
				Assume.assumeNoException(e);
			}
		}
		finally {
			if (online) {
				serverOffline.put(port, false);
				if (!assumeOnline) {
					Assume.assumeTrue(serverOffline.get(port));
				}

			}
			else {
				serverOnline.put(port, false);
			}
		}

		tokenServer = null;
		if (isLegacy()) {
			tokenServer = new LegacyTokenServer();
			try {
				logger.debug("Starting legacy token server");
				tokenServer.init();
			}
			catch (Exception e) {
				logger.error("Could not start legacy token server", e);
				Assert.fail("Could not start legacy token server");
			}
		}

		return new Statement() {

			@Override
			public void evaluate() throws Throwable {

				try {
					base.evaluate();
				}
				finally {
					if (tokenServer != null) {
						try {
							tokenServer.close();
						}
						catch (Exception e) {
							logger.error("Could not stop legacy token server", e);
						}
					}
				}
			}

		};

	}

	public String getBaseUrl() {
		return "http://" + hostName + (port == 80 ? "" : ":" + port) + rootPath;
	}

	public String getUrl(String path) {
		if (path.startsWith("http:")) {
			return path;
		}
		if (!path.startsWith("/")) {
			path = "/" + path;
		}
		return getBaseUrl() + path;
	}

	public ResponseEntity<String> postForString(String path, MultiValueMap<String, String> formData) {
		return postForString(path, formData, new HttpHeaders());
	}

	public ResponseEntity<String> postForString(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
		if (headers.getContentType() == null) {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		}
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				headers), String.class);
	}

	@SuppressWarnings("rawtypes")
	public ResponseEntity<Map> postForMap(String path, MultiValueMap<String, String> formData) {
		return postForMap(path, formData, new HttpHeaders());
	}

	@SuppressWarnings("rawtypes")
	public ResponseEntity<Map> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
		if (headers.getContentType() == null) {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		}
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				headers), Map.class);
	}

	public ResponseEntity<String> getForString(String path) {
		return client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<Void>((Void) null), String.class);
	}

	public <T> ResponseEntity<T> getForObject(String path, Class<T> type) {
		return client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<Void>((Void) null), type);
	}

	public ResponseEntity<String> getForString(String path, final HttpHeaders headers) {
		HttpEntity<Void> request = new HttpEntity<Void>(null, headers);
		return client.exchange(getUrl(path), HttpMethod.GET, request, String.class);
	}

	public ResponseEntity<Void> getForResponse(String path, final HttpHeaders headers, Object... uriVariables) {
		HttpEntity<Void> request = new HttpEntity<Void>(null, headers);
		return client.exchange(getUrl(path), HttpMethod.GET, request, null, uriVariables);
	}

	public ResponseEntity<Void> postForResponse(String path, HttpHeaders headers, MultiValueMap<String, String> params) {
		HttpHeaders actualHeaders = new HttpHeaders();
		actualHeaders.putAll(headers);
		actualHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(params,
				actualHeaders), null);
	}

	public ResponseEntity<Void> postForRedirect(String path, HttpHeaders headers, MultiValueMap<String, String> params) {
		ResponseEntity<Void> exchange = postForResponse(path, headers, params);

		if (exchange.getStatusCode() != HttpStatus.FOUND) {
			throw new IllegalStateException("Expected 302 but server returned status code " + exchange.getStatusCode());
		}

		if (exchange.getHeaders().containsKey("Set-Cookie")) {
			String cookie = exchange.getHeaders().getFirst("Set-Cookie");
			headers.set("Cookie", cookie);
		}

		String location = exchange.getHeaders().getLocation().toString();

		return client.exchange(location, HttpMethod.GET, new HttpEntity<Void>(null, headers), null);
	}

	public RestTemplate getRestTemplate() {
		if (client == null) {
			client = createRestTemplate();
		}
		return client;
	}

	public void setRestTemplate(RestTemplate restTemplate) {
		this.client = restTemplate;
	}

	public RestTemplate createRestTemplate() {
		RestTemplate client = new RestTemplate();
		client.setRequestFactory(new HttpComponentsClientHttpRequestFactory() {
			@Override
			public HttpClient getHttpClient() {
				HttpClient client = super.getHttpClient();
				client.getParams().setBooleanParameter(ClientPNames.HANDLE_REDIRECTS, false);
				client.getParams().setParameter(ClientPNames.COOKIE_POLICY, CookiePolicy.IGNORE_COOKIES);
				return client;
			}
		});
		client.setErrorHandler(new ResponseErrorHandler() {
			// Pass errors through in response entity for status code analysis
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return false;
			}

			public void handleError(ClientHttpResponse response) throws IOException {
			}
		});
		return client;
	}

	public UriBuilder buildUri(String url) {
		return UriBuilder.fromUri(url.startsWith("http:") ? url : getUrl(url));
	}

	public static class UriBuilder {

		private final String url;

		private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

		public UriBuilder(String url) {
			this.url = url;
		}

		public static UriBuilder fromUri(String url) {
			return new UriBuilder(url);
		}

		public UriBuilder queryParam(String key, String value) {
			params.add(key, value);
			return this;
		}

		public URI build() {
			StringBuilder builder = new StringBuilder(url);
			try {
				if (!params.isEmpty()) {
					builder.append("?");
					boolean first = true;
					for (String key : params.keySet()) {
						if (!first) {
							builder.append("&");
						}
						else {
							first = false;
						}
						for (String value : params.get(key)) {
							builder.append(key + "=" + UriUtils.encodeQueryParam(value, "UTF-8"));
						}
					}
				}
				return new URI(builder.toString());
			}
			catch (UnsupportedEncodingException ex) {
				// should not happen, UTF-8 is always supported
				throw new IllegalStateException(ex);
			}
			catch (URISyntaxException ex) {
				throw new IllegalArgumentException("Could not create URI from [" + builder + "]: " + ex, ex);
			}
		}

	}

}
