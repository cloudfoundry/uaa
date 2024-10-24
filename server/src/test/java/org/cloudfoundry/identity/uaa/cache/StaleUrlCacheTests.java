package org.cloudfoundry.identity.uaa.cache;

import com.github.benmanes.caffeine.cache.Ticker;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaleUrlCacheTests {

    private static final Duration CACHE_EXPIRATION = Duration.ofMinutes(10);
    private static final Duration CACHE_EXPIRED = CACHE_EXPIRATION.multipliedBy(2).plusMinutes(1);
    private static final String URI = "http://localhost:8080/uaa/.well-known/openid-configuration";
    private static final byte[] content1;
    private static final byte[] content2;
    private static final byte[] content3;

    static {
        content1 = new byte[8];
        Arrays.fill(content1, (byte) 1);
        content2 = new byte[8];
        Arrays.fill(content2, (byte) 2);
        content3 = new byte[8];
        Arrays.fill(content3, (byte) 3);
    }

    @Mock
    HttpEntity<?> httpEntity;
    @Mock
    ResponseEntity<byte[]> responseEntity;
    private StaleUrlCache cache;
    @Mock
    private TimeService mockTimeService;
    @Mock
    private RestTemplate mockRestTemplate;
    private TestTicker ticker;

    @BeforeEach
    void setup() {
        ticker = new TestTicker(System.nanoTime());
        cache = new StaleUrlCache(CACHE_EXPIRATION, mockTimeService, 2, ticker);
        reset(mockRestTemplate);
    }

    @Test
    void correct_method_invoked_on_rest_template() throws URISyntaxException {
        cache.getUrlContent(URI, mockRestTemplate);
        verify(mockRestTemplate, times(1)).getForObject(eq(new URI(URI)), same(byte[].class));
    }

    @Test
    void incorrect_uri_throws_illegal_argument_exception() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> cache.getUrlContent("invalid value", mockRestTemplate));
    }

    @Test
    void rest_client_exception_is_propagated() {
        when(mockRestTemplate.getForObject(any(URI.class), any())).thenThrow(new RestClientException("mock"));
        assertThatExceptionOfType(RestClientException.class).isThrownBy(() -> cache.getUrlContent(URI, mockRestTemplate));
    }

    @Test
    void calling_twice_uses_cache() throws Exception {
        byte[] c1 = cache.getUrlContent(URI, mockRestTemplate);
        byte[] c2 = cache.getUrlContent(URI, mockRestTemplate);
        verify(mockRestTemplate, times(1)).getForObject(eq(new URI(URI)), same(byte[].class));
        assertThat(c2).isSameAs(c1);
        assertThat(cache.size()).isOne();
    }

    @Test
    void entry_refreshes_after_time() {
        when(mockTimeService.getCurrentTimeMillis()).thenAnswer(e -> System.currentTimeMillis());
        when(mockRestTemplate.getForObject(any(URI.class), any())).thenReturn(content1, content2, content3);

        // populate the cache
        byte[] c1 = cache.getUrlContent(URI, mockRestTemplate);
        ticker.advance(CACHE_EXPIRED);

        // next call after timeout, should force async refresh
        byte[] c2 = cache.getUrlContent(URI, mockRestTemplate);
        assertThat(c2).isSameAs(c1);

        // Allow time for the async getUrlContent to be called
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> verify(mockRestTemplate, times(2)).getForObject(eq(new URI(URI)), same(byte[].class)));
        // Allow time for the async update to caffeine's cache.
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> assertThat(cache.getUrlContent(URI, mockRestTemplate)).isNotSameAs(c1));
    }

    @Test
    void cache_should_start_empty() {
        assertThat(cache.size()).isZero();
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
        for (String aUri : Arrays.asList(uri1, uri1, uri2, uri2, uri3, uri3)) {
            cache.getUrlContent(aUri, mockRestTemplate);
        }
        for (String aUri : Arrays.asList(uri1, uri2, uri3)) {
            verify(mockRestTemplate, times(1)).getForObject(eq(new URI(aUri)), same(byte[].class));
        }
        cache.cleanUp();
        assertThat(cache.size()).isEqualTo(2);
    }

    @Test
    void stale_entry_returned_on_failure() {
        when(mockRestTemplate.getForObject(any(URI.class), any())).thenReturn(content3).thenThrow(new RestClientException("mock"));

        // populate the cache
        byte[] c1 = cache.getUrlContent(URI, mockRestTemplate);
        ticker.advance(CACHE_EXPIRED);

        // next call after timeout, should force async refresh
        byte[] c2 = cache.getUrlContent(URI, mockRestTemplate);
        assertThat(c2).isSameAs(c1);

        // Allow time for the async getUrlContent to be called
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> verify(mockRestTemplate, times(2)).getForObject(eq(new URI(URI)), same(byte[].class)));
        // Allow time for the async update to caffeine's cache.
        // It should continue returning the stale content due to the exception
        await().during(200, TimeUnit.MILLISECONDS).untilAsserted(() -> assertThat(cache.getUrlContent(URI, mockRestTemplate)).isSameAs(c1));
    }

    @Test
    void extended_method_invoked_on_rest_template() throws URISyntaxException {
        when(mockRestTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(responseEntity);
        when(responseEntity.getStatusCode()).thenReturn(HttpStatus.OK);
        when(responseEntity.getBody()).thenReturn(new byte[1]);
        cache.getUrlContent(URI, mockRestTemplate, HttpMethod.GET, httpEntity);
        verify(mockRestTemplate, times(1)).exchange(eq(new URI(URI)),
                eq(HttpMethod.GET), any(HttpEntity.class), same(byte[].class));
    }

    @Test
    void extended_method_invoked_on_rest_template_invalid_http_response() {
        when(mockRestTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(responseEntity);
        when(responseEntity.getStatusCode()).thenReturn(HttpStatus.TEMPORARY_REDIRECT);
        assertThatThrownBy(() -> cache.getUrlContent(URI, mockRestTemplate, HttpMethod.GET, httpEntity))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_executed() {
        StaleUrlCache urlCache = new StaleUrlCache(mockTimeService);
        urlCache.clear();
        cache.cleanUp();

        assertThat(urlCache.size()).isZero();
    }

    static class TestTicker implements Ticker {
        long nanos;

        public TestTicker(long initialNanos) {
            nanos = initialNanos;
        }

        @Override
        public long read() {
            return nanos;
        }

        public void advance(Duration duration) {
            nanos += duration.toNanos();
        }
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

            String url = slowHttpServer.getUrl();
            await().atMost(60, TimeUnit.SECONDS).untilAsserted(() ->
                    assertThatThrownBy(() -> cache.getUrlContent(url, restTemplate))
                            .isInstanceOf(ResourceAccessException.class));
        }
    }
}
