package org.cloudfoundry.identity.uaa.cache;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.RemovalListener;
import com.github.benmanes.caffeine.cache.Ticker;
import com.google.common.util.concurrent.UncheckedExecutionException;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;

@Slf4j
public class StaleUrlCache implements UrlContentCache {
    private static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final LoadingCache<UriRequest, CacheEntry> cache;

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
        Caffeine<Object, Object> builder = Caffeine.newBuilder()
                .refreshAfterWrite(cacheExpiration)
                .maximumSize(maxEntries)
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
    public byte[] getUrlContent(String uri, final RestTemplate template, final HttpMethod method,
            HttpEntity<?> requestEntity) {
        try {
            return cache.get(new UriRequest(uri, template, method, requestEntity)).data;
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

        UriRequest(String uri, RestTemplate template, HttpMethod method, HttpEntity<?> requestEntity) {
            this.uri = uri;
            this.template = template;
            this.method = method;
            this.requestEntity = requestEntity;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + (uri == null ? 0 : uri.hashCode());
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
            if (uri == null) {
                return other.uri == null;
            } else {
                return uri.equals(other.uri);
            }
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
                byte[] metadata;
                final URI netUri = new URI(request.uri);
                if (request.requestEntity != null) {
                    ResponseEntity<byte[]> responseEntity = request.template.exchange(netUri, request.method,
                            request.requestEntity, byte[].class);
                    if (responseEntity.getStatusCode() == HttpStatus.OK) {
                        metadata = responseEntity.getBody();
                    } else {
                        throw new IllegalArgumentException(
                                "Unable to fetch content, status:" + HttpStatus.resolve(responseEntity.getStatusCode().value()).getReasonPhrase());
                    }
                } else {
                    metadata = request.template.getForObject(netUri, byte[].class);
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
