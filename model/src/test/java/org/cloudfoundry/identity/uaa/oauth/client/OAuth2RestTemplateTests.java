package org.cloudfoundry.identity.uaa.oauth.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;

import org.cloudfoundry.identity.uaa.oauth.client.http.AccessTokenRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProviderChain;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;

import org.springframework.util.ReflectionUtils;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.util.UriTemplate;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2RestTemplateTests {

  private BaseOAuth2ProtectedResourceDetails resource;

  private OAuth2RestTemplate restTemplate;

  private AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);

  private ClientHttpRequest request;

  private HttpHeaders headers;

  @Before
  public void open() throws Exception {
    resource = new BaseOAuth2ProtectedResourceDetails();
    // Facebook and older specs:
    resource.setTokenName("bearer_token");
    restTemplate = new OAuth2RestTemplate(resource);
    restTemplate.setAccessTokenProvider(accessTokenProvider);
    request = Mockito.mock(ClientHttpRequest.class);
    headers = new HttpHeaders();
    Mockito.when(request.getHeaders()).thenReturn(headers);
    ClientHttpResponse response = Mockito.mock(ClientHttpResponse.class);
    HttpStatus statusCode = HttpStatus.OK;
    Mockito.when(response.getStatusCode()).thenReturn(statusCode);
    Mockito.when(request.execute()).thenReturn(response);
  }

  @Test
  public void testNonBearerToken() throws Exception {
    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
    token.setTokenType("MINE");
    restTemplate.getOAuth2ClientContext().setAccessToken(token);
    ClientHttpRequest http = restTemplate.createRequest(URI.create("https://nowhere.com/api/crap"), HttpMethod.GET);
    String auth = http.getHeaders().getFirst("Authorization");
    assertTrue(auth.startsWith("MINE "));
  }

  @Test
  public void testCustomAuthenticator() throws Exception {
    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
    token.setTokenType("MINE");
    restTemplate.setAuthenticator(new OAuth2RequestAuthenticator() {
      @Override
      public void authenticate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext clientContext, ClientHttpRequest req) {
        req.getHeaders().set("X-Authorization", clientContext.getAccessToken().getTokenType() + " " + "Nah-nah-na-nah-nah");
      }
    });
    restTemplate.getOAuth2ClientContext().setAccessToken(token);
    ClientHttpRequest http = restTemplate.createRequest(URI.create("https://nowhere.com/api/crap"), HttpMethod.GET);
    String auth = http.getHeaders().getFirst("X-Authorization");
    assertEquals("MINE Nah-nah-na-nah-nah", auth);
  }

  /**
   * tests appendQueryParameter
   */
  @Test
  public void testAppendQueryParameter() throws Exception {
    OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
    URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search?type=checkin"),
        token);
    assertEquals("https://graph.facebook.com/search?type=checkin&bearer_token=12345", appended.toString());
  }

  /**
   * tests appendQueryParameter
   */
  @Test
  public void testAppendQueryParameterWithNoExistingParameters() throws Exception {
    OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
    URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
    assertEquals("https://graph.facebook.com/search?bearer_token=12345", appended.toString());
  }

  /**
   * tests encoding of access token value
   */
  @Test
  public void testDoubleEncodingOfParameterValue() throws Exception {
    OAuth2AccessToken token = new DefaultOAuth2AccessToken("1/qIxxx");
    URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
    assertEquals("https://graph.facebook.com/search?bearer_token=1%2FqIxxx", appended.toString());
  }

  /**
   * tests no double encoding of existing query parameter
   */
  @Test
  public void testNonEncodingOfUriTemplate() throws Exception {
    OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
    UriTemplate uriTemplate = new UriTemplate("https://graph.facebook.com/fql?q={q}");
    URI expanded = uriTemplate.expand("[q: fql]");
    URI appended = restTemplate.appendQueryParameter(expanded, token);
    assertEquals("https://graph.facebook.com/fql?q=%5Bq:%20fql%5D&bearer_token=12345", appended.toString());
  }

  /**
   * tests URI with fragment value
   */
  @Test
  public void testFragmentUri() throws Exception {
    OAuth2AccessToken token = new DefaultOAuth2AccessToken("1234");
    URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search#foo"), token);
    assertEquals("https://graph.facebook.com/search?bearer_token=1234#foo", appended.toString());
  }

  /**
   * tests encoding of access token value passed in protected requests ref: SECOAUTH-90
   */
  @Test
  public void testDoubleEncodingOfAccessTokenValue() throws Exception {
    // try with fictitious token value with many characters to encode
    OAuth2AccessToken token = new DefaultOAuth2AccessToken("1 qI+x:y=z");
    // System.err.println(UriUtils.encodeQueryParam(token.getValue(), "UTF-8"));
    URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
    assertEquals("https://graph.facebook.com/search?bearer_token=1+qI%2Bx%3Ay%3Dz", appended.toString());
  }

  @Test(expected = AccessTokenRequiredException.class)
  public void testNoRetryAccessDeniedExceptionForNoExistingToken() throws Exception {
    restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
    restTemplate.setRequestFactory(new ClientHttpRequestFactory() {
      public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
        throw new AccessTokenRequiredException(resource);
      }
    });
    restTemplate.doExecute(new URI("https://foo"), HttpMethod.GET, new NullRequestCallback(),
        new SimpleResponseExtractor());
  }

  @Test
  public void testRetryAccessDeniedException() throws Exception {
    final AtomicBoolean failed = new AtomicBoolean(false);
    restTemplate.getOAuth2ClientContext().setAccessToken(new DefaultOAuth2AccessToken("TEST"));
    restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
    restTemplate.setRequestFactory(new ClientHttpRequestFactory() {
      public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
        if (!failed.get()) {
          failed.set(true);
          throw new AccessTokenRequiredException(resource);
        }
        return request;
      }
    });
    Boolean result = restTemplate.doExecute(new URI("https://foo"), HttpMethod.GET, new NullRequestCallback(),
        new SimpleResponseExtractor());
    assertTrue(result);
  }

  @Test
  public void testNewTokenAcquiredIfExpired() throws Exception {
    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
    token.setExpiration(new Date(System.currentTimeMillis() - 1000));
    restTemplate.getOAuth2ClientContext().setAccessToken(token);
    restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
    OAuth2AccessToken newToken = restTemplate.getAccessToken();
    assertNotNull(newToken);
    assertTrue(!token.equals(newToken));
  }

  // gh-1478
  @Test
  public void testNewTokenAcquiredWithDefaultClockSkew() {
    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
    token.setExpiration(new Date(System.currentTimeMillis() + 29000));	// Default clock skew is 30 secs
    restTemplate.getOAuth2ClientContext().setAccessToken(token);
    restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
    OAuth2AccessToken newToken = restTemplate.getAccessToken();
    assertNotNull(newToken);
    assertTrue(!token.equals(newToken));
  }

  // gh-1478
  @Test
  public void testNewTokenAcquiredIfLessThanConfiguredClockSkew() {
    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
    token.setExpiration(new Date(System.currentTimeMillis() + 5000));
    restTemplate.setClockSkew(6);
    restTemplate.getOAuth2ClientContext().setAccessToken(token);
    restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
    OAuth2AccessToken newToken = restTemplate.getAccessToken();
    assertNotNull(newToken);
    assertTrue(!token.equals(newToken));
  }

  // gh-1478
  @Test
  public void testNewTokenNotAcquiredIfGreaterThanConfiguredClockSkew() {
    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
    token.setExpiration(new Date(System.currentTimeMillis() + 5000));
    restTemplate.setClockSkew(4);
    restTemplate.getOAuth2ClientContext().setAccessToken(token);
    restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
    OAuth2AccessToken newToken = restTemplate.getAccessToken();
    assertNotNull(newToken);
    assertTrue(token.equals(newToken));
  }

  // gh-1478
  @Test(expected = IllegalArgumentException.class)
  public void testNegativeClockSkew() {
    restTemplate.setClockSkew(-1);
  }

  // gh-1909
  @Test
  public void testClockSkewPropagationIntoAccessTokenProviderChain() {
    AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Collections.<AccessTokenProvider>emptyList());
    restTemplate.setAccessTokenProvider(accessTokenProvider);
    restTemplate.setClockSkew(5);

    Field field = ReflectionUtils.findField(accessTokenProvider.getClass(), "clockSkew");
    field.setAccessible(true);

    assertEquals(5, ReflectionUtils.getField(field, accessTokenProvider));
  }

  // gh-1909
  @Test
  public void testApplyClockSkewOnProvidedAccessTokenProviderChain() {
    AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Collections.<AccessTokenProvider>emptyList());
    restTemplate.setClockSkew(5);
    restTemplate.setAccessTokenProvider(accessTokenProvider);

    Field field = ReflectionUtils.findField(accessTokenProvider.getClass(), "clockSkew");
    field.setAccessible(true);

    assertEquals(5, ReflectionUtils.getField(field, accessTokenProvider));
  }

  // gh-1909
  @Test
  public void testClockSkewPropagationSkippedForNonAccessTokenProviderChainInstances() {
    restTemplate.setClockSkew(5);
    restTemplate.setAccessTokenProvider(null);
    restTemplate.setClockSkew(5);
    restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
    restTemplate.setClockSkew(5);
  }

  @Test
  public void testTokenIsResetIfInvalid() throws Exception {
    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
    token.setExpiration(new Date(System.currentTimeMillis() - 1000));
    restTemplate.getOAuth2ClientContext().setAccessToken(token);
    restTemplate.setAccessTokenProvider(new StubAccessTokenProvider() {
      @Override
      public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details,
          AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException {
        throw new UserRedirectRequiredException("https://www.foo.com/", Collections.<String, String> emptyMap());
      }
    });
    try {
      OAuth2AccessToken newToken = restTemplate.getAccessToken();
      assertNotNull(newToken);
      fail("Expected UserRedirectRequiredException");
    }
    catch (UserRedirectRequiredException e) {
      // planned
    }
    // context token should be reset as it clearly is invalid at this point
    assertNull(restTemplate.getOAuth2ClientContext().getAccessToken());
  }

  private final class SimpleResponseExtractor implements ResponseExtractor<Boolean> {
    public Boolean extractData(ClientHttpResponse response) throws IOException {
      return true;
    }
  }

  private static class NullRequestCallback implements RequestCallback {
    public void doWithRequest(ClientHttpRequest request) throws IOException {
    }
  }

  private static class StubAccessTokenProvider implements AccessTokenProvider {
    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest parameters)
        throws UserRedirectRequiredException, AccessDeniedException {
      return new DefaultOAuth2AccessToken("FOO");
    }

    public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
      return false;
    }

    public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
        OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
      return null;
    }

    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
      return true;
    }
  }

}
