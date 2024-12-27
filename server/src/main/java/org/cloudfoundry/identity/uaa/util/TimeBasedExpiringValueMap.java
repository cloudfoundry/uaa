/*
 * *****************************************************************************
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
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Not a concurrent map, but works like a HashMap
 * Expires entries that have not been fetched in timeout
 *
 * @param <K> key type
 * @param <V> value type
 */
public class TimeBasedExpiringValueMap<K, V> {

    public static final long DEFALT_TIMEOUT = 1_000L * 2 * 60;

    private final TimeService timeService;
    private final Map<K, TimedKeyValue> map;
    private final long timeout;
    private final AtomicLong lastCheck = new AtomicLong(0);

    public TimeBasedExpiringValueMap(TimeService timeService) {
        this(timeService, DEFALT_TIMEOUT);
    }

    public TimeBasedExpiringValueMap(TimeService timeService, long timeoutMilliseconds) {
        this.timeService = timeService;
        this.map = new ConcurrentHashMap<>();
        this.timeout = timeoutMilliseconds;
    }

    public void put(K key, V value) {
        TimedKeyValue v = new TimedKeyValue(timeService.getCurrentTimeMillis(), key, value);
        map.put(key, v);
        expireCheck();
    }

    public V get(K key) {
        TimedKeyValue<K, V> v = map.get(key);
        if (v != null) {
            //optimized for fast retrieval
            removeExpired(v);
            return v.getValue();
        }
        //we got a miss. maybe others expired
        //hijack the caller thread for this operation
        expireCheck();
        return null;
    }

    public V remove(K key) {
        TimedKeyValue<K, V> v = map.remove(key);
        if (v != null) {
            return v.getValue();
        }
        return null;
    }

    public int size() {
        return map.size();
    }

    public void clear() {
        map.clear();
    }

    protected void expireCheck() {
        long now = timeService.getCurrentTimeMillis();
        long l = lastCheck.get();
        if ((now - l) > timeout) {
            //time for an expiry check
            if (lastCheck.compareAndSet(l, now)) {
                Map.Entry[] entries = map.entrySet().toArray(new Map.Entry[0]);
                for (Map.Entry<K, TimedKeyValue> entry : entries) {
                    removeExpired(entry.getValue());
                }
            }
        }
    }

    protected boolean hasExpired(long time) {
        long now = timeService.getCurrentTimeMillis();
        return (now - time) > timeout;
    }

    protected boolean removeExpired(TimedKeyValue<K, V> timedKeyValue) {
        if (timedKeyValue != null && hasExpired(timedKeyValue.getTime())) {
            TimedKeyValue remove = map.remove(timedKeyValue.getKey());
            if (remove != null && hasExpired(remove.getTime())) {
                return true;
            }
            //value has been replaced since we decided to expire it
            //replace it only if there isn't one
            map.putIfAbsent(timedKeyValue.getKey(), timedKeyValue);
        }
        return false;
    }

}
