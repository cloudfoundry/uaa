/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  *******************************************************************************
 */

package org.cloudfoundry.identity.uaa.cache;

import com.google.common.base.Ticker;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

public class ExpiringUrlCache implements UrlContentCache {
    private static final Logger logger = LoggerFactory.getLogger(ExpiringUrlCache.class);

    private final Duration cacheExpiration;
    private final TimeService timeService;
    private final Cache<String, CacheEntry> cache;

    public ExpiringUrlCache(Duration cacheExpiration, TimeService timeService, int maxEntries) {
        this.cacheExpiration = cacheExpiration;
        this.timeService = timeService;
        cache = CacheBuilder
                .newBuilder()
                .expireAfterWrite(this.cacheExpiration.toMillis(), TimeUnit.MILLISECONDS)
                .maximumSize(maxEntries)
                .ticker(Ticker.systemTicker())
                .build();
    }

    @Override
    public byte[] getUrlContent(String uri, final RestTemplate template) {
        try {
            final URI netUri = new URI(uri);
            CacheEntry entry = cache.getIfPresent(uri);
            byte[] metadata = entry != null ? entry.data : null;
            if (metadata == null || isEntryExpired(entry)) {
                logger.debug("Fetching metadata for "+uri);
                metadata = template.getForObject(netUri, byte[].class);
                Instant now = Instant.ofEpochMilli(timeService.getCurrentTimeMillis());
                cache.put(uri, new CacheEntry(now, metadata));
            }
            return metadata;
        } catch (RestClientException x) {
            logger.warn("Unable to fetch metadata for "+uri, x);
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
