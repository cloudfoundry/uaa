package org.cloudfoundry.identity.uaa.cache;

import com.google.common.base.Ticker;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Component
public class ExpiringUrlCache implements UrlContentCache {
    private static final Logger logger = LoggerFactory.getLogger(ExpiringUrlCache.class);
    private static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final Duration cacheExpiration;
    private final TimeService timeService;
    private final Cache<String, CacheEntry> cache;

    @Autowired
    public ExpiringUrlCache(final TimeService timeService) {
        this(Duration.ofMinutes(10), timeService, DEFAULT_MAX_ENTRIES);
    }

    public ExpiringUrlCache(
            final Duration cacheExpiration,
            final TimeService timeService,
            final int maxEntries) {
        this.cacheExpiration = cacheExpiration;
        this.timeService = timeService;
        this.cache = CacheBuilder
                .newBuilder()
                .expireAfterWrite(this.cacheExpiration.toMillis(), TimeUnit.MILLISECONDS)
                .maximumSize(maxEntries)
                .ticker(Ticker.systemTicker())
                .build();
    }

    @Override
    public byte[] getUrlContent(String uri, final RestTemplate template) {
        return getUrlContent(uri, template, HttpMethod.GET, null);
    }

    @Override
    public byte[] getUrlContent(String uri, final RestTemplate template, final HttpMethod method, HttpEntity<?> requestEntity) {
        try {
            final URI netUri = new URI(uri);
            CacheEntry entry = cache.getIfPresent(uri);
            byte[] metadata = entry != null ? entry.data : null;
            if (metadata == null || isEntryExpired(entry)) {
                logger.debug("Fetching metadata for " + uri);
                if (requestEntity != null) {
                    ResponseEntity<byte[]> responseEntity = template.exchange(netUri, method, requestEntity, byte[].class);
                    if (responseEntity.getStatusCode() == HttpStatus.OK) {
                        metadata = responseEntity.getBody();
                    } else {
                        throw new IllegalArgumentException("Unable to fetch content, status:" + responseEntity.getStatusCode().getReasonPhrase());
                    }
                } else {
                    metadata = template.getForObject(netUri, byte[].class);
                }
                Instant now = Instant.ofEpochMilli(timeService.getCurrentTimeMillis());
                cache.put(uri, new CacheEntry(now, metadata));
            }
            return metadata;
        } catch (RestClientException x) {
            logger.warn("Unable to fetch metadata for {0}. {1}", uri, x.getMessage());
            throw x;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private boolean isEntryExpired(CacheEntry entry) {
        Instant now = Instant.ofEpochMilli(timeService.getCurrentTimeMillis());
        return Duration.between(entry.timeEntered, now).compareTo(cacheExpiration) > 0;
    }

    @Override
    public void clear() {
        cache.invalidateAll();
    }

    @Override
    public long size() {
        return cache.size();
    }

    static class CacheEntry {
        final Instant timeEntered;
        final byte[] data;

        CacheEntry(Instant timeEntered, byte[] data) {
            this.timeEntered = timeEntered;
            this.data = data;
        }
    }
}
