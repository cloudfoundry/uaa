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
 * @param <K> key type
 * @param <V> value type
 */
public class TimeBasedExpiringValueMap<K,V> {

    public static final long DEFALT_TIMEOUT = 2 * 1000 * 60;

    private final TimeService timeService;
    private final Map<K,Value> map;
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
        Value v = new Value(timeService.getCurrentTimeMillis(), key, value);
        map.put(key, v);
        expireCheck();
    }

    public V get(K key) {
        Value v = map.get(key);
        if (v!=null) {
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
        Value v = map.remove(key);
        if (v!=null) {
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
        if ( (now - l) > timeout) {
            //time for an expiry check
            if (lastCheck.compareAndSet(l,now)) {
                Map.Entry[] entries = map.entrySet().toArray(new Map.Entry[0]);
                for (Map.Entry<K, Value> entry : entries) {
                    removeExpired(entry.getValue());
                }
            }
        }
    }

    protected boolean hasExpired(long time) {
        long now = timeService.getCurrentTimeMillis();
        return (now - time) > timeout;
    }

    protected boolean removeExpired(Value value) {
        if ( hasExpired(value.getTime()) ) {
            Value remove = map.remove(value.getKey());
            if (hasExpired(remove.getTime())) {
                return true;
            }
            //value has been replaced since we decided to expire it
            //replace it only if there isn't one
            map.putIfAbsent(value.getKey(), value);
        }
        return false;
    }

    private class Value {
        final long time;
        final K key;
        final V value;

        private Value(long time, K key, V value) {
            this.time = time;
            this.value = value;
            this.key = key;
        }

        public V getValue() {
            return value;
        }

        public K getKey() {
            return key;
        }

        public long getTime() {
            return time;
        }
    }
}
