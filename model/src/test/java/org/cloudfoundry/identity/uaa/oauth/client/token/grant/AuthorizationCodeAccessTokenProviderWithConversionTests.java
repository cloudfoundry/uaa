package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.oauth.client.grant.AuthorizationCodeAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class AuthorizationCodeAccessTokenProviderWithConversionTests {

	private static class StubClientHttpRequest implements ClientHttpRequest {

		private static final HttpHeaders DEFAULT_RESPONSE_HEADERS = new HttpHeaders();

		private final HttpStatus responseStatus;

		private final HttpHeaders responseHeaders;

		private final String responseBody;

		{
			DEFAULT_RESPONSE_HEADERS.setContentType(MediaType.APPLICATION_JSON);
		}

		public StubClientHttpRequest(String responseBody) {
			this(HttpStatus.OK, DEFAULT_RESPONSE_HEADERS, responseBody);
		}

		public StubClientHttpRequest(HttpHeaders responseHeaders, String responseBody) {
			this(HttpStatus.OK, responseHeaders, responseBody);
		}

		public StubClientHttpRequest(HttpStatus responseStatus, String responseBody) {
			this(responseStatus, DEFAULT_RESPONSE_HEADERS, responseBody);
		}

		public StubClientHttpRequest(HttpStatus responseStatus, HttpHeaders responseHeaders, String responseBody) {
			this.responseStatus = responseStatus;
			this.responseHeaders = responseHeaders;
			this.responseBody = responseBody;
		}

		public OutputStream getBody() throws IOException {
			return new ByteArrayOutputStream();
		}

		public HttpHeaders getHeaders() {
			return new HttpHeaders();
		}

		public URI getURI() {
			try {
				return new URI("https://www.foo.com/");
			}
			catch (URISyntaxException e) {
				throw new IllegalStateException(e);
			}
		}

		public HttpMethod getMethod() {
			return HttpMethod.POST;
		}

		public String getMethodValue() {
			return getMethod().name();
		}

		public ClientHttpResponse execute() throws IOException {
			return new ClientHttpResponse() {

				public HttpHeaders getHeaders() {
					return responseHeaders;
				}

				public InputStream getBody() throws IOException {
					return new ByteArrayInputStream(responseBody.getBytes("UTF-8"));
				}

				public String getStatusText() throws IOException {
					return responseStatus.getReasonPhrase();
				}

				public HttpStatus getStatusCode() throws IOException {
					return responseStatus;
				}

				public void close() {
				}

				public int getRawStatusCode() throws IOException {
					return responseStatus.value();
				}
			};
		}
	}

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private ClientHttpRequestFactory requestFactory;

	private AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();

	private AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();

	private void setUpRestTemplate() {
		provider.setRequestFactory(requestFactory);
	}

	@Test
	public void testGetAccessTokenFromJson() throws Exception {
		final OAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		requestFactory = new ClientHttpRequestFactory() {
			public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
				return new StubClientHttpRequest(new ObjectMapper().writeValueAsString(token));
			}
		};
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setAuthorizationCode("foo");
		resource.setAccessTokenUri("http://localhost/oauth/token");
		request.setPreservedState(new Object());
		setUpRestTemplate();
		assertEquals(token, provider.obtainAccessToken(resource, request));
	}

	@Test
	public void testGetErrorFromJson() throws Exception {
		final InvalidClientException exception = new InvalidClientException("FOO");
		requestFactory = new ClientHttpRequestFactory() {
			public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
				return new StubClientHttpRequest(HttpStatus.BAD_REQUEST,
						new ObjectMapper().writeValueAsString(exception));
			}
		};
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setAuthorizationCode("foo");
		request.setPreservedState(new Object());
		resource.setAccessTokenUri("http://localhost/oauth/token");
		expected.expect(OAuth2AccessDeniedException.class);
		expected.expect(hasCause(instanceOf(InvalidClientException.class)));
		setUpRestTemplate();
		provider.obtainAccessToken(resource, request);
	}

	@Test
	public void testGetAccessTokenFromForm() throws Exception {
		final OAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		final HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		requestFactory = new ClientHttpRequestFactory() {
			public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
				return new StubClientHttpRequest(responseHeaders, "access_token=FOO");
			}
		};
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setAuthorizationCode("foo");
		request.setPreservedState(new Object());
		resource.setAccessTokenUri("http://localhost/oauth/token");
		setUpRestTemplate();
		assertEquals(token, provider.obtainAccessToken(resource, request));
	}

	@Test
	public void testGetErrorFromForm() throws Exception {
		final HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		requestFactory = new ClientHttpRequestFactory() {
			public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
				return new StubClientHttpRequest(HttpStatus.BAD_REQUEST, responseHeaders,
						"error=invalid_client&error_description=FOO");
			}
		};
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setAuthorizationCode("foo");
		request.setPreservedState(new Object());
		resource.setAccessTokenUri("http://localhost/oauth/token");
		expected.expect(OAuth2AccessDeniedException.class);
		expected.expect(hasCause(instanceOf(InvalidClientException.class)));
		setUpRestTemplate();
		provider.obtainAccessToken(resource, request);
	}

	private Matcher<Throwable> hasCause(final Matcher<?> matcher) {
		return new TypeSafeMatcher<Throwable>() {
			public void describeTo(Description description) {
				description.appendText("exception matching ");
				description.appendDescriptionOf(matcher);
			}

			@Override
			public boolean matchesSafely(Throwable item) {
				return matcher.matches(item.getCause());
			}
		};
	}

}
