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

package org.cloudfoundry.identity.uaa.metrics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class IdleTimerTests {

    public static final int LOOP_COUNT = 100000;
    private IdleTimer timer;
    public static final int THREAD_COUNT = 10;

    @BeforeEach
    void setup() {
        timer = new IdleTimer();
    }

    @Test
    void timer_started() throws Exception {
        Thread.sleep(10);
        assertThat(timer.getInflightRequests()).isZero();
        assertThat(timer.getRunTime()).isPositive();
        assertThat(timer.getIdleTime()).isPositive();
    }

    @Test
    void illegal_end_request() {
        assertThatThrownBy(() -> timer.endRequest())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Illegal end request invocation, no request in flight");
    }

    @Test
    void while_inflight() throws Exception {
        timer.startRequest();
        long idleTime = timer.getIdleTime();
        assertThat(timer.getInflightRequests()).isOne();
        timer.startRequest();
        assertThat(timer.getInflightRequests()).isEqualTo(2);
        timer.endRequest();
        assertThat(timer.getInflightRequests()).isOne();
        Thread.sleep(10);
        assertThat(timer.getIdleTime()).as("Idle time should not have changed.").isEqualTo(idleTime);
        timer.endRequest();
        assertThat(timer.getInflightRequests()).isZero();
        Thread.sleep(10);
        assertThat(timer.getIdleTime()).as("Idle time should have changed.").isGreaterThan(idleTime);
    }

    @Test
    void concurrency_test() throws Exception {
        final CountDownLatch latch = new CountDownLatch(THREAD_COUNT);
        Thread[] threads = new Thread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i] = new Thread(() -> {
                for (int loop = 0; loop < LOOP_COUNT; loop++) {
                    try {
                        timer.startRequest();
                    } finally {
                        timer.endRequest();
                    }
                }
                latch.countDown();
            });
        }
        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].start();
        }
        latch.await();
        assertThat(timer.getRequestCount()).isEqualTo(THREAD_COUNT * LOOP_COUNT);
        assertThat(timer.getInflightRequests()).isZero();
    }
}
