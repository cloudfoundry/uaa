package org.cloudfoundry.identity.uaa.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Arrays;

import com.google.common.testing.FakeTicker;

import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

class StaleUrlCacheTests {

  private static final Duration CACHE_EXPIRATION = Duration.ofMinutes(10);
  private static final String uri = "http://localhost:8080/uaa/.well-known/openid-configuration";
  private static final byte[] content;

  private StaleUrlCache cache;
  private TimeService mockTimeService;
  private RestTemplate mockRestTemplate;
  private FakeTicker ticker;

  static {
    content = new byte[1024];
    Arrays.fill(content, (byte) 1);
  }

  @BeforeEach
  void setup() {
    mockTimeService = mock(TimeService.class);
    when(mockTimeService.getCurrentTimeMillis()).thenAnswer(e -> System.currentTimeMillis());
    ticker = new FakeTicker();
    cache = new StaleUrlCache(CACHE_EXPIRATION, mockTimeService, 2, ticker);
    mockRestTemplate = mock(RestTemplate.class);
    reset(mockRestTemplate);
    when(mockRestTemplate.getForObject(any(URI.class), any())).thenReturn(content, new byte[1024]);
  }

  @Test
  void correct_method_invoked_on_rest_template() throws URISyntaxException {
    cache.getUrlContent(uri, mockRestTemplate);
    verify(mockRestTemplate, times(1)).getForObject(eq(new URI(uri)), same(byte[].class));
  }

  @Test
  void incorrect_uri_throws_illegal_argument_exception() {
    assertThrows(IllegalArgumentException.class, () -> cache.getUrlContent("invalid value", mockRestTemplate));
  }

  @Test
  void rest_client_exception_is_propagated() {
    when(mockRestTemplate.getForObject(any(URI.class), any())).thenThrow(new RestClientException("mock"));
    assertThrows(RestClientException.class, () -> cache.getUrlContent(uri, mockRestTemplate));
  }

  @Test
  void calling_twice_uses_cache() throws Exception {
    byte[] c1 = cache.getUrlContent(uri, mockRestTemplate);
    byte[] c2 = cache.getUrlContent(uri, mockRestTemplate);
    verify(mockRestTemplate, times(1)).getForObject(eq(new URI(uri)), same(byte[].class));
    assertSame(c1, c2);
    assertEquals(1, cache.size());
  }

  @Test
  void entry_expires_on_time() throws Exception {
    System.err.println("eeot: " + ticker.read());
    byte[] c1 = cache.getUrlContent(uri, mockRestTemplate);
    ticker.advance(Duration.ofMillis(CACHE_EXPIRATION.toMillis() + 1));
    System.err.println("eeot: " + ticker.read());
    byte[] c2 = cache.getUrlContent(uri, mockRestTemplate);
    verify(mockRestTemplate, times(2)).getForObject(eq(new URI(uri)), same(byte[].class));
    assertNotSame(c1, c2);
  }

  @Test
  void cache_should_start_empty() {
    assertEquals(0, cache.size());
  }

  @Test
  void max_entries_is_respected() throws URISyntaxException {
    String uri1 = "http://test1.com";
    String uri2 = "http://test2.com";
    String uri3 = "http://test3.com";
    byte[] c1 = new byte[1024];
    byte[] c2 = new byte[1024];
    byte[] c3 = new byte[1024];
    mockRestTemplate = mock(RestTemplate.class);
    when(mockRestTemplate.getForObject(eq(new URI(uri1)), any())).thenReturn(c1);
    when(mockRestTemplate.getForObject(eq(new URI(uri2)), any())).thenReturn(c2);
    when(mockRestTemplate.getForObject(eq(new URI(uri3)), any())).thenReturn(c3);
    for (String uri : Arrays.asList(uri1, uri1, uri2, uri2, uri3, uri3)) {
      cache.getUrlContent(uri, mockRestTemplate);
    }
    for (String uri : Arrays.asList(uri1, uri2, uri3)) {
      verify(mockRestTemplate, times(1)).getForObject(eq(new URI(uri)), same(byte[].class));
    }
    assertEquals(2, cache.size());
  }

  @Test
  void stale_entry_returned_on_failure() throws Exception {
    System.err.println("serof: " + ticker.read());
    byte[] c1 = cache.getUrlContent(uri, mockRestTemplate);
    ticker.advance(Duration.ofMillis(CACHE_EXPIRATION.toMillis() + 1));
    System.err.println("serof: " + ticker.read());
    when(mockRestTemplate.getForObject(any(URI.class), any())).thenThrow(new RestClientException("mock"));
    byte[] c2 = cache.getUrlContent(uri, mockRestTemplate);
    verify(mockRestTemplate, times(2)).getForObject(eq(new URI(uri)), same(byte[].class));
    assertSame(c1, c2);
  }

  @Test
  public void extended_method_invoked_on_rest_template() throws URISyntaxException {
    HttpEntity httpEntity = mock(HttpEntity.class);
    ResponseEntity<byte[]> responseEntity = mock(ResponseEntity.class);
    when(mockRestTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(responseEntity);
    when(responseEntity.getStatusCode()).thenReturn(HttpStatus.OK);
    when(responseEntity.getBody()).thenReturn(new byte[1]);
    cache.getUrlContent(uri, mockRestTemplate, HttpMethod.GET, httpEntity);
    verify(mockRestTemplate, times(1)).exchange(eq(new URI(uri)),
        eq(HttpMethod.GET), any(HttpEntity.class),same(byte[].class));
  }

  @Test
  public void extended_method_invoked_on_rest_template_invalid_http_response() throws URISyntaxException {
    HttpEntity httpEntity = mock(HttpEntity.class);
    ResponseEntity<byte[]> responseEntity = mock(ResponseEntity.class);
    when(mockRestTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(responseEntity);
    when(responseEntity.getStatusCode()).thenReturn(HttpStatus.TEMPORARY_REDIRECT);
    assertThrows(IllegalArgumentException.class, () -> cache.getUrlContent(uri, mockRestTemplate, HttpMethod.GET, httpEntity));
  }

  @Test
  public void constructor_executed() throws URISyntaxException {
    StaleUrlCache urlCache = new StaleUrlCache(mockTimeService);
    urlCache.clear();
    assertEquals(0, urlCache.size());
  }

  @Nested
  @DisplayName("When a http server never returns a http response")
  class DeadHttpServer {
    private SlowHttpServer slowHttpServer;

    @BeforeEach
    void startHttpServer() {
      slowHttpServer = new SlowHttpServer();
      slowHttpServer.run();
    }

    @AfterEach
    void stopHttpServer() {
      slowHttpServer.stop();
    }

    @Test
    void throwUnavailableIdpWhenServerMetadataDoesNotReply() {
      RestTemplateConfig restTemplateConfig = RestTemplateConfig.createDefaults();
      restTemplateConfig.timeout = 120;
      RestTemplate restTemplate = restTemplateConfig.trustingRestTemplate();

      assertTimeout(Duration.ofSeconds(60), () -> assertThrows(ResourceAccessException.class,
          () -> cache.getUrlContent(slowHttpServer.getUrl(), restTemplate)));
    }
  }
}
