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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;

public class ExpiringUrlCache implements UrlContentCache {

    private static Log logger = LogFactory.getLog(ExpiringUrlCache.class);

    private final long expiringTimeMillis;
    private final int maxEntries;
    private final TimeService ticker;
    protected Cache<String, CacheEntry> cache = null;

    public ExpiringUrlCache(long expiringTimeMillis, TimeService ticker, int maxEntries) {
        this.expiringTimeMillis = expiringTimeMillis;
        this.ticker = ticker;
        this.maxEntries = maxEntries;
        cache = CacheBuilder
            .newBuilder()
            .expireAfterWrite(expiringTimeMillis, TimeUnit.MILLISECONDS)
            .maximumSize(maxEntries)
            .ticker(Ticker.systemTicker())
            .build();
    }


    @Override
    public byte[] getUrlContent(String uri, final RestTemplate template) {
        try {
            final URI netUri = new URI(uri);
            CacheEntry entry = cache.getIfPresent(uri);
            byte[] metadata = entry != null ? entry.getData() : null;
            long now = ticker.getCurrentTimeMillis();
            if (metadata == null || (now - entry.getTimeEntered()) > this.expiringTimeMillis) {
                logger.debug("Fetching metadata for "+uri);
                metadata = template.getForObject(netUri, byte[].class);
                cache.put(uri, new CacheEntry(now, metadata));
            }
            return metadata;
        } catch (RestClientException x) {
            logger.warn("Unable to fetch metadata for "+uri, x);
            return null;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
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
        private final long timeEntered;
        private final byte[] data;

        public CacheEntry(long timeEntered, byte[] data) {
            this.timeEntered = timeEntered;
            this.data = data;
        }

        public long getTimeEntered() {
            return timeEntered;
        }

        public byte[] getData() {
            return data;
        }

    }
}
