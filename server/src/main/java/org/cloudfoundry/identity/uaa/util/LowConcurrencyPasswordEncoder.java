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

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@ManagedResource(
    objectName="cloudfoundry.identity:name=BcryptConcurrency",
    description = "Bcrypt Concurrency"
)
public class LowConcurrencyPasswordEncoder implements PasswordEncoder {

    private static Log logger = LogFactory.getLog(LowConcurrencyPasswordEncoder.class);

    private final PasswordEncoder delegate;
    private final int max;
    private final BlockingQueue<BcrypWaitingResource> exchange;
    private final long timeoutMs;
    private final AtomicLong counter = new AtomicLong(0);

    public LowConcurrencyPasswordEncoder(PasswordEncoder delegate, long timeoutMs, boolean enabled) {
        this(delegate, timeoutMs, enabled, Runtime.getRuntime());
    }

    protected LowConcurrencyPasswordEncoder(PasswordEncoder delegate, long timeoutMs, boolean enabled, Runtime runtime) {
        this.delegate = delegate;
        this.timeoutMs = timeoutMs;
        int processors = runtime.availableProcessors();
        if (enabled) {
            switch (processors) {
                case 1 : max = 1; break;
                case 2 : max = 1; break;
                case 3 : max = 2; break;
                case 4 : max = 3; break;
                default: max = processors-2;
            }
            exchange = new FairBlockingQueue<>();
            for (int i = 0; i < max; i++) {
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

    @Override
    public String encode(CharSequence rawPassword) throws AuthenticationException {
        try (BcrypWaitingResource waiting = waitIfWeNeedTo()) {
            logger.debug("Bcrypt proceed with "+waiting.getName());
            return delegate.encode(rawPassword);
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) throws AuthenticationException {
        try (BcrypWaitingResource waiting = waitIfWeNeedTo()) {
            logger.debug("Bcrypt proceed with "+waiting.getName());
            return delegate.matches(rawPassword, encodedPassword);
        }
    }

    public BcrypWaitingResource waitIfWeNeedTo() throws AuthenticationServiceException {
        long request = counter.incrementAndGet();
        try {
            if (exchange!=null) {
                BcrypWaitingResource resource = exchange.poll(timeoutMs, TimeUnit.MILLISECONDS);
                if (resource == null) {
                    //TODO we should throw some sort of authentication exception
                    throw new AuthenticationServiceException("System resources busy. Try again.");
                } else {
                    return resource;
                }
            } else {
                return new BcrypWaitingResource(null, "Request nr:"+request) {
                    @Override
                    public void close() {
                        //no op
                    }
                };
            }
        } catch (InterruptedException e) {
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

