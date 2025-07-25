package org.cloudfoundry.identity.uaa.cache;

import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;
import com.github.benmanes.caffeine.cache.Ticker;
import com.google.common.util.concurrent.UncheckedExecutionException;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.jspecify.annotations.Nullable;
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
    private static final Duration CACHE_EXPIRED = CACHE_EXPIRATION.plusMinutes(1);
    private static final String URL = "http://localhost:8080/uaa/.well-known/openid-configuration";
    private static final byte[] content1;
    private static final byte[] content2;
    private static final byte[] content3;

    private StaleUrlCache cache;
    @Mock
    private TimeService mockTimeService;
    @Mock
    private RestTemplate mockRestTemplate;
    @Mock
    HttpEntity<?> httpEntity;
    @Mock
    ResponseEntity<byte[]> responseEntity;

    private TestTicker ticker;

    static {
        content1 = new byte[8];
        Arrays.fill(content1, (byte) 1);
        content2 = new byte[8];
        Arrays.fill(content2, (byte) 2);
        content3 = new byte[8];
        Arrays.fill(content3, (byte) 3);
    }

    static class DetectRemovalListener implements RemovalListener<Object, Object> {
        volatile int removalCount = 0;

        @Override
        public void onRemoval(@Nullable Object key, @Nullable Object value, RemovalCause cause) {
            removalCount++;
        }
    }

    private DetectRemovalListener listener;

    @BeforeEach
    void setup() {
        ticker = new TestTicker(System.nanoTime());

        listener = new DetectRemovalListener();

        cache = new StaleUrlCache(CACHE_EXPIRATION, mockTimeService, 2, ticker, listener);
        reset(mockRestTemplate);
    }

    @Test
    void correct_method_invoked_on_rest_template() throws URISyntaxException {
        cache.getUrlContent(URL, mockRestTemplate);
        verify(mockRestTemplate, times(1)).getForObject(eq(new URI(URL)), same(byte[].class));
    }

    @Test
    void incorrect_uri_throws_illegal_argument_exception() {
        assertThatThrownBy(() -> cache.getUrlContent("invalid value", mockRestTemplate))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rest_client_exception_is_propagated() {
        when(mockRestTemplate.getForObject(any(URI.class), any())).thenThrow(new RestClientException("mock"));
        assertThatThrownBy(() -> cache.getUrlContent(URL, mockRestTemplate))
                .isInstanceOf(RestClientException.class);
    }

    @Test
    void calling_twice_uses_cache() throws Exception {
        byte[] c1 = cache.getUrlContent(URL, mockRestTemplate);
        byte[] c2 = cache.getUrlContent(URL, mockRestTemplate);
        verify(mockRestTemplate, times(1)).getForObject(eq(new URI(URL)), same(byte[].class));
        assertThat(c2).isSameAs(c1);
        assertThat(cache.size()).isOne();
    }

    @Test
    void entry_refreshes_after_time() {
        when(mockTimeService.getCurrentTimeMillis()).thenAnswer(e -> System.currentTimeMillis());
        when(mockRestTemplate.getForObject(any(URI.class), any())).thenReturn(content1, content2, content3);

        // populate the cache
        byte[] c1 = cache.getUrlContent(URL, mockRestTemplate);
        ticker.advance(CACHE_EXPIRED);

        // the next call after timeout should force async refresh and return the new value
        // This call is necessary to trigger the cache refresh operation after the timeout period.
        cache.getUrlContent(URL, mockRestTemplate);
        await().atMost(5, TimeUnit.SECONDS).untilAsserted(
                () -> assertThat(listener.removalCount).isGreaterThan(0)
        );
        byte[] c2 = cache.getUrlContent(URL, mockRestTemplate);
        assertThat(c2).isSameAs(content2);

        // Allow time for the async getUrlContent to be called
        await().atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> verify(mockRestTemplate, times(2))
                        .getForObject(eq(new URI(URL)), same(byte[].class))
                );

        // Allow time for the async update to caffeine's cache.
        await().atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(cache.getUrlContent(URL, mockRestTemplate))
                        .isNotSameAs(c1)
                );
    }

    @Test
    void cache_should_start_empty() {
        assertThat(cache.size()).isZero();
    }

    @Test
    void max_entries_is_respected() throws URISyntaxException {
        String uri1 = "https://test1.com";
        String uri2 = "https://test2.com";
        String uri3 = "https://test3.com";
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
        byte[] c1 = cache.getUrlContent(URL, mockRestTemplate);
        ticker.advance(CACHE_EXPIRED);

        // next call after timeout, should force async refresh
        byte[] c2 = cache.getUrlContent(URL, mockRestTemplate);
        assertThat(c2).isSameAs(c1);

        // Allow time for the async getUrlContent to be called
        await().atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> verify(mockRestTemplate, times(2))
                        .getForObject(eq(new URI(URL)), same(byte[].class))
                );

        // Allow time for the async update to caffeine's cache.
        // It should continue returning the stale content due to the exception
        await().during(200, TimeUnit.MILLISECONDS)
                .untilAsserted(() -> assertThat(cache.getUrlContent(URL, mockRestTemplate))
                        .isSameAs(c1)
                );
    }

    @Test
    void extended_method_invoked_on_rest_template() throws URISyntaxException {
        when(mockRestTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(responseEntity);
        when(responseEntity.getStatusCode()).thenReturn(HttpStatus.OK);
        when(responseEntity.getBody()).thenReturn(new byte[1]);
        cache.getUrlContent(URL, mockRestTemplate, HttpMethod.GET, httpEntity);
        verify(mockRestTemplate, times(1)).exchange(eq(new URI(URL)),
                eq(HttpMethod.GET), any(HttpEntity.class), same(byte[].class));
    }

    @Test
    void exception_invoked_on_rest_template() {
        when(mockRestTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), any(Class.class)))
                .thenThrow(new UncheckedExecutionException(new IllegalArgumentException("illegal")));
        assertThatThrownBy(() -> cache.getUrlContent(URL, mockRestTemplate, HttpMethod.GET, httpEntity))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equal() {
        StaleUrlCache.UriRequest uriRequest = new StaleUrlCache.UriRequest(URL, mockRestTemplate, HttpMethod.GET, responseEntity);
        assertThat(uriRequest)
                .isEqualTo(uriRequest)
                .isNotEqualTo(null)
                .isNotEqualTo(URL);
        assertThat(new StaleUrlCache.UriRequest(URL, mockRestTemplate, HttpMethod.GET, responseEntity)).isEqualTo(uriRequest);
        assertThat(new StaleUrlCache.UriRequest(null, mockRestTemplate, HttpMethod.GET, responseEntity)).isNotEqualTo(uriRequest);
    }

    @Test
    void extended_method_invoked_on_rest_template_invalid_http_response() {
        when(mockRestTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(responseEntity);
        when(responseEntity.getStatusCode()).thenReturn(HttpStatus.TEMPORARY_REDIRECT);
        assertThatThrownBy(() -> cache.getUrlContent(URL, mockRestTemplate, HttpMethod.GET, httpEntity))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_executed() {
        StaleUrlCache urlCache = new StaleUrlCache(mockTimeService);
        urlCache.clear();
        cache.cleanUp();

        assertThat(urlCache.size()).isZero();
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
            await().atMost(60, TimeUnit.SECONDS)
                    .untilAsserted(() -> assertThatThrownBy(() -> cache.getUrlContent(url, restTemplate))
                            .isInstanceOf(ResourceAccessException.class)
                    );
        }
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
}
