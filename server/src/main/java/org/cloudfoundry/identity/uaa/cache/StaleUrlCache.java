package org.cloudfoundry.identity.uaa.cache;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.RemovalListener;
import com.github.benmanes.caffeine.cache.Ticker;
import com.google.common.util.concurrent.UncheckedExecutionException;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.util.BoundedHttpFetch;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

@Slf4j
public class StaleUrlCache implements UrlContentCache {
    private static final int DEFAULT_MAX_ENTRIES = 10_000;
    // The cache is bounded by total response bytes (maxEntries * WEIGHT_BYTES_PER_ENTRY).
    private static final long WEIGHT_BYTES_PER_ENTRY = 10 * 1024L;

    private final LoadingCache<UriRequest, CacheEntry> cache;
    // A response larger than the whole cache budget could never be retained, so it is not read either.
    private final int defaultMaxResponseBytes;

    public StaleUrlCache(final TimeService timeService) {
        this(timeService, Ticker.systemTicker());
    }

    public StaleUrlCache(final TimeService timeService, final Ticker ticker) {
        this(Duration.ofMinutes(10), timeService, DEFAULT_MAX_ENTRIES, ticker);
    }

    public StaleUrlCache(final Duration cacheExpiration, final TimeService timeService, final int maxEntries,
            final Ticker ticker) {
        this(cacheExpiration, timeService, maxEntries, ticker, null);
    }

    public StaleUrlCache(final Duration cacheExpiration, final TimeService timeService, final int maxEntries,
                         final Ticker ticker, RemovalListener<Object, Object> listener) {
        long maximumWeight = maxEntries * WEIGHT_BYTES_PER_ENTRY;
        this.defaultMaxResponseBytes = (int) Math.min(Integer.MAX_VALUE, maximumWeight);
        Caffeine<Object, Object> builder = Caffeine.newBuilder()
                .refreshAfterWrite(cacheExpiration)
                .maximumWeight(maximumWeight)
                // Every entry costs at least one per-entry share, so maxEntries still bounds the entry count.
                .weigher((k, v) -> {
                    if (v instanceof CacheEntry ce && ce.data != null) {
                        return Math.max(ce.data.length, (int) WEIGHT_BYTES_PER_ENTRY);
                    }
                    return (int) WEIGHT_BYTES_PER_ENTRY;
                })
                .ticker(ticker);
        if (listener != null) {
            builder = builder.evictionListener(listener).removalListener(listener);
        }

        this.cache = builder.build(new UrlCacheLoader(timeService));
    }

    @Override
    public byte[] getUrlContent(String uri, final RestTemplate template) {
        return getUrlContent(uri, template, HttpMethod.GET, null);
    }

    @Override
    public byte[] getUrlContent(String uri, final RestTemplate template, final int maxResponseBytes) {
        return get(new UriRequest(uri, template, HttpMethod.GET, null, Math.min(maxResponseBytes, defaultMaxResponseBytes)));
    }

    @Override
    public byte[] getUrlContent(String uri, final RestTemplate template, final HttpMethod method,
            HttpEntity<?> requestEntity) {
        return get(new UriRequest(uri, template, method, requestEntity, defaultMaxResponseBytes));
    }

    private byte[] get(UriRequest request) {
        try {
            return cache.get(request).data;
        } catch (UncheckedExecutionException e) {
            log.warn("UncheckedException {}", e.getMessage(), e);
            throw (RuntimeException) e.getCause();
        }
    }

    @Override
    public void clear() {
        cache.invalidateAll();
    }

    @Override
    public void cleanUp() {
        cache.cleanUp();
    }

    @Override
    public long size() {
        return cache.estimatedSize();
    }

    static class UriRequest {
        final String uri;
        final RestTemplate template;
        final HttpMethod method;
        final HttpEntity<?> requestEntity;

        // Part of equals/hashCode, so a caller's limit only ever decides the outcome of loads for that same limit.
        final int maxResponseBytes;

        UriRequest(String uri, RestTemplate template, HttpMethod method, HttpEntity<?> requestEntity) {
            this(uri, template, method, requestEntity, Integer.MAX_VALUE);
        }

        UriRequest(String uri, RestTemplate template, HttpMethod method, HttpEntity<?> requestEntity, int maxResponseBytes) {
            this.uri = uri;
            this.template = template;
            this.method = method;
            this.requestEntity = requestEntity;
            this.maxResponseBytes = maxResponseBytes;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + (uri == null ? 0 : uri.hashCode());
            result = prime * result + maxResponseBytes;
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            UriRequest other = (UriRequest) obj;
            return Objects.equals(uri, other.uri) && maxResponseBytes == other.maxResponseBytes;
        }
    }

    static class CacheEntry {
        final Instant timeEntered;
        final byte[] data;

        CacheEntry(Instant timeEntered, byte[] data) {
            this.timeEntered = timeEntered;
            this.data = data;
        }
    }

    class UrlCacheLoader implements CacheLoader<UriRequest, CacheEntry> {

        private final TimeService timeService;

        UrlCacheLoader(TimeService timeService) {
            this.timeService = timeService;
        }

        @Override
        public CacheEntry load(UriRequest request) throws RuntimeException {
            try {
                final URI netUri = new URI(request.uri);
                // Same callbacks as getForObject/exchange(..., byte[].class): headers, body and Accept are unchanged.
                RequestCallback requestCallback = request.requestEntity != null
                        ? request.template.httpEntityCallback(request.requestEntity, byte[].class)
                        : request.template.acceptHeaderRequestCallback(byte[].class);
                byte[] metadata = BoundedHttpFetch.fetch(request.template, netUri, request.method, requestCallback,
                        request.maxResponseBytes, request.requestEntity != null);
                if (metadata.length == 0) {
                    metadata = null;
                }
                Instant now = Instant.ofEpochMilli(timeService.getCurrentTimeMillis());
                return new CacheEntry(now, metadata);
            } catch (RestClientException x) {
                log.warn("Unable to fetch metadata for {}: {}", request.uri, x.getMessage());
                throw x;
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException(e);
            }
        }
    }
}
