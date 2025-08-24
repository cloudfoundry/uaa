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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.concurrent.ConcurrentMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TimeBasedExpiringValueMapTest {

    public static final int TIMEOUT = 50;
    private final MockTimeService timeService = new MockTimeService();
    private TimeBasedExpiringValueMap<String, Object> map;
    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private final String key1 = generator.generate();
    private final String key2 = generator.generate();
    private final Object value1 = new Object();
    private final Object value2 = new Object();

    @BeforeEach
    void setUp() {
        map = new TimeBasedExpiringValueMap<>(timeService, TIMEOUT);
    }

    @Test
    void no_value() {
        assertThat(map.get(generator.generate())).isNull();
    }

    @Test
    void put_then_get() {
        map.put(key1, value1);
        assertThat(map.get(key1)).isSameAs(value1);
    }

    @Test
    void clear() {
        map.put(key1, value1);
        assertThat(map.get(key1)).isNotNull();
        assertThat(map.size()).isOne();
        map.clear();
        assertThat(map.get(key1)).isNull();
        assertThat(map.size()).isZero();
    }

    @Test
    void expire_on_get() {
        map.put(key1, value1);
        timeService.addAndGet(TIMEOUT * 2);
        assertThat(map.size()).isOne();
        assertThat(map.get(key1)).isSameAs(value1);
        assertThat(map.size()).isZero();
        assertThat(map.get(key1)).isNull();
    }

    @Test
    void expire_on_put() {
        map.put(key1, value1);
        assertThat(map.size()).isOne();
        timeService.addAndGet(TIMEOUT * 2);
        map.put(key2, value2);
        assertThat(map.size()).isOne();
    }

    @Test
    void remove() {
        map.put(key1, value1);
        assertThat(map.remove(key1)).isSameAs(value1);
        assertThat(map.size()).isZero();
    }

    @Test
    void non_existent_remove() {
        assertThat(map.remove("does-not-exist")).isNull();
    }

    @Test
    void concurrency_test() throws Exception {
        TimeServiceImpl timeService = mock(TimeServiceImpl.class);
        when(timeService.getCurrentTimeMillis()).thenReturn(1L);

        map = new TimeBasedExpiringValueMap<>(timeService, 0);
        AlphanumericRandomValueStringGenerator randomValueStringGenerator = new AlphanumericRandomValueStringGenerator(1);

        Thread[] threads = new Thread[2];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> {
                String key = randomValueStringGenerator.generate().toLowerCase();
                Object value = new Object();
                map.put(key, value);
                assertThat(map.get(key)).isNotNull();
            });
        }
        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
        assertThat(map.size()).isPositive();

        when(timeService.getCurrentTimeMillis()).thenReturn(Long.MAX_VALUE);
        map.get("random-key");
        assertThat(map.size()).isZero();
    }

    @Test
    void avoid_npe_during_remove() {
        map = new TimeBasedExpiringValueMap<>(new TimeServiceImpl(), TIMEOUT);
        ConcurrentMap internalMap = mock(ConcurrentMap.class);
        TimedKeyValue<String, Object> value = new TimedKeyValue<>(0, "test", new Object());
        when(internalMap.remove(any())).thenReturn(null);
        ReflectionTestUtils.setField(map, "map", internalMap);
        assertThat(map.removeExpired(value)).isFalse();
        verify(internalMap, times(1)).putIfAbsent(same(value.key), same(value));
        assertThat(map.removeExpired(null)).isFalse();
    }

}