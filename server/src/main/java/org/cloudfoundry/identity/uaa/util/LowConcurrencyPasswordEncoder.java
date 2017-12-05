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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.tomcat.jdbc.pool.FairBlockingQueue;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Concurrency limiting implementation of the password encoder.
 * This implementation has the following goals
 * - limit the number of concurrent threads that can run bcrypt at any given time
 * - use a `majority` of the CPU resources available when available
 * - threads that can't run bcrypt should be queued as `first come first out` fashion
 *
 * We can compare this implementation to a track relay race.
 * - there are 8 lanes on the track
 * - each lane hosts a team of 4 runners
 * - only one runner per team can run at any given time
 * - to accomplish this, each team gets one baton.
 * - if a runner has a baton, that runner can run
 * - the runner can only hand off the baton to the next in line runner
 *
 * The implementation uses a FairBlockingQueue from the tomcat-jdbc implementation.
 * The queue has a set of batons, a baton is implemented using a `BcrypWaitingResource` object.
 * The FairBlockingQueue is loaded up with X number of BcrypWaitingResource objects,
 * one object for each thread that can run at any given time.
 *
 * The concurrency limiter works like this
 * 1. when a thread arrives it requests a BcryptWaitingResource from the blocking queue
 * 2. if no items are available, the queue will block the thread in an ordered fashion
 * 3. when a BcryptWaitingResource is available in the queue the thread will be unblocked
 * 4. as long as the thread holds the BcryptWaitingResource it can proceed with operations
 * 5. when the thread has completed the bcrypt operation it returns the BcryptWaitingResource to the queue
 * 6. if there is a thread blocked by the queue, that thread picks up the BcryptWaitingResource and proceeds with the bcrypt call
 */
@ManagedResource(
    objectName="cloudfoundry.identity:name=BcryptConcurrency",
    description = "Bcrypt Concurrency"
)
public class LowConcurrencyPasswordEncoder implements PasswordEncoder {

    private static Log logger = LogFactory.getLog(LowConcurrencyPasswordEncoder.class);

    //the bcrypt implementation
    private final PasswordEncoder delegate;
    //max number of threads running bcrypt at any given time
    private final int max;
    //thread limiting queue
    private final BlockingQueue<BcrypWaitingResource> exchange;
    //the number of milliseconds to wait for bcrypt
    private final long timeoutMs;
    //request counter
    private final AtomicLong counter = new AtomicLong(0);

    protected LowConcurrencyPasswordEncoder(PasswordEncoder delegate, long timeoutMs, boolean enabled, RuntimeEnvironment environment) {
        this.delegate = delegate;
        this.timeoutMs = timeoutMs;
        int processors = environment.availableProcessors();
        if (enabled) {
            //determine how many concurrent threads can run
            //given the number of CPUs are available on the system
            switch (processors) {
                case 1 : max = 1; break;
                case 2 : max = 1; break;
                case 3 : max = 2; break;
                case 4 : max = 3; break;
                default: max = processors-2;
            }
            //instantiate a blocking queue
            exchange = new FairBlockingQueue<>();

            for (int i = 0; i < max; i++) {
                //populate the blocking queue with 'max' number of batons
                exchange.offer(new BcrypWaitingResource(exchange, "LowConcurrency Waiter Nr:" + counter.incrementAndGet()));
            }
        } else {
            exchange = null;
            max = processors;
        }
    }

    @ManagedMetric(category = "scalability", displayName = "Max Bcrypt Threads")
    public int getMax() {
        return max;
    }

    @ManagedMetric(category = "scalability", displayName = "Current Bcrypt Executions")
    public int getCurrent() {
        return max - exchange.size();
    }

    @ManagedMetric(
        category = "scalability",
        displayName = "Bcrypt Threads Waiting",
        description = "Approximate number of threads waiting to perform a bcrypt operation."
    )
    public int getWaiters() {
        try {
            Field waiters = ReflectionUtils.findField(exchange.getClass(), "waiters");
            ReflectionUtils.makeAccessible(waiters);
            Object actualWaiters = waiters.get(exchange);
            Method size = ReflectionUtils.findMethod(actualWaiters.getClass(), "size");
            return (Integer)ReflectionUtils.invokeMethod(size, actualWaiters);
        } catch (Exception e) {
            logger.debug("Unable to read waiter size", e);
        }
        return -1;
    }

    @Override
    public String encode(CharSequence rawPassword) throws AuthenticationException {
        try (BcrypWaitingResource waiting = waitIfWeNeedTo()) { //wait for a baton
            //we now have the baton, we can proceed
            logger.debug("Bcrypt encode proceed with "+waiting.getName());
            return delegate.encode(rawPassword);
        } //this automatically calls waiting.close()
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) throws AuthenticationException {
        try (BcrypWaitingResource waiting = waitIfWeNeedTo()) { //wait for a baton
            //we now have the baton, we can proceed
            logger.debug("Bcrypt matches proceed with "+waiting.getName());
            return delegate.matches(rawPassword, encodedPassword);
        } //this automatically calls waiting.close()
    }

    public BcrypWaitingResource waitIfWeNeedTo() throws AuthenticationServiceException {
        long request = counter.incrementAndGet();
        try {
            if (exchange!=null) {
                //request a baton from the queue
                BcrypWaitingResource resource = exchange.poll(timeoutMs, TimeUnit.MILLISECONDS);
                if (resource == null) { //we timed out. throw an authentication exception to the caller
                    throw new AuthenticationServiceException("System resources busy. Try again.");
                } else { //success
                    return resource;
                }
            } else { //concurrency is disabled. provide a no-op baton
                return new BcrypWaitingResource(null, "Request nr:"+request) { @Override public void close() { }};
            }
        } catch (InterruptedException e) {
            //system interruption of the thread should be treated the same as a timeout
            throw new AuthenticationServiceException("Bcrypt thread was interrupted, unable to validate.", e);
        }
    }



    private static class BcrypWaitingResource implements AutoCloseable {

        private final BlockingQueue<BcrypWaitingResource> exchange;
        private final String name;

        private BcrypWaitingResource(BlockingQueue<BcrypWaitingResource> exchange, String name) {
            this.exchange = exchange;
            this.name= name;
        }

        public String getName() {
            return name;
        }

        @Override
        public void close() {
            exchange.offer(this);
        }
    }
}

