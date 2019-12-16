/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.util;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.concurrent.ConcurrentMap;

import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class TimeBasedExpiringValueMapTest {

    public static final int TIMEOUT = 50;
    private MockTimeService timeService = new MockTimeService();
    private TimeBasedExpiringValueMap<String, Object> map;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String key1 = generator.generate(), key2 = generator.generate();
    private Object value1 = new Object(), value2 = new Object();

    @Before
    public void setUp() {
        map = new TimeBasedExpiringValueMap<>(timeService, TIMEOUT);
    }

    @Test
    public void no_value() {
        assertNull(map.get(generator.generate()));
    }

    @Test
    public void put_then_get() {
        map.put(key1, value1);
        assertSame(value1, map.get(key1));
    }

    @Test
    public void clear() {
        map.put(key1, value1);
        assertNotNull(map.get(key1));
        assertEquals(1, map.size());
        map.clear();
        assertNull(map.get(key1));
        assertEquals(0, map.size());
    }

    @Test
    public void expire_on_get() {
        map.put(key1, value1);
        timeService.addAndGet(TIMEOUT * 2);
        assertEquals(1, map.size());
        assertSame(value1, map.get(key1));
        assertEquals(0, map.size());
        assertNull(map.get(key1));
    }

    @Test
    public void expire_on_put() {
        map.put(key1, value1);
        assertEquals(1, map.size());
        timeService.addAndGet(TIMEOUT * 2);
        map.put(key2, value2);
        assertEquals(1, map.size());
    }

    @Test
    public void remove() {
        map.put(key1, value1);
        assertSame(value1, map.remove(key1));
        assertEquals(0, map.size());
    }

    @Test
    public void non_existent_remove() {
        assertNull(map.remove("does-not-exist"));
    }

    @Test
    public void concurrency_test() throws Exception {
        TimeServiceImpl timeService = mock(TimeServiceImpl.class);
        when(timeService.getCurrentTimeMillis()).thenReturn(1L);

        map = new TimeBasedExpiringValueMap<>(timeService, 0);
        RandomValueStringGenerator randomValueStringGenerator = new RandomValueStringGenerator(1);

        Thread[] threads = new Thread[2];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> {
                String key = randomValueStringGenerator.generate().toLowerCase();
                Object value = new Object();
                map.put(key, value);
                assertNotNull(map.get(key));
            });
        }
        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
        assertThat(map.size(), greaterThan(0));

        when(timeService.getCurrentTimeMillis()).thenReturn(Long.MAX_VALUE);
        map.get("random-key");
        assertEquals(0, map.size());
    }

    @Test
    public void avoid_npe_during_remove() {
        map = new TimeBasedExpiringValueMap<>(new TimeServiceImpl(), TIMEOUT);
        ConcurrentMap internalMap = mock(ConcurrentMap.class);
        TimedKeyValue<String, Object> value = new TimedKeyValue<>(0, "test", new Object());
        when(internalMap.remove(any())).thenReturn(null);
        ReflectionTestUtils.setField(map, "map", internalMap);
        assertFalse(map.removeExpired(value));
        verify(internalMap, times(1)).putIfAbsent(same(value.key), same(value));
        assertFalse(map.removeExpired(null));
    }

}