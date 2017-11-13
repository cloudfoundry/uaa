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
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.concurrent.TimeUnit;

@ManagedResource(
    objectName="cloudfoundry.identity:name=BcryptConcurrency",
    description = "Bcrypt Concurrency"
)
public class LowConcurrencyPasswordEncoder implements PasswordEncoder {

    private static Log logger = LogFactory.getLog(LowConcurrencyPasswordEncoder.class);

    private final PasswordEncoder delegate;
    private final int max;
    private final FairBlockingQueue<BcrypWaitingResource> exchange = new FairBlockingQueue<>();
    private final long timeoutMs;

    public LowConcurrencyPasswordEncoder(PasswordEncoder delegate, long timeoutMs) {
        this.delegate = delegate;
        this.timeoutMs = timeoutMs;
        max = Math.max(1, Runtime.getRuntime().availableProcessors() / 2);
        for (int i=0; i<max; i++) {
            exchange.offer(new BcrypWaitingResource(exchange,"LowConcurrency Waiter Nr:"+i));
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
    public String encode(CharSequence rawPassword) {
        try (BcrypWaitingResource waiting = waitIfWeNeedTo()) {
            logger.debug("Bcrypt proceed with "+waiting.getName());
            return delegate.encode(rawPassword);
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        try (BcrypWaitingResource waiting = waitIfWeNeedTo()) {
            logger.debug("Bcrypt proceed with "+waiting.getName());
            return delegate.matches(rawPassword, encodedPassword);
        }
    }


    public BcrypWaitingResource waitIfWeNeedTo() {
        try {
            BcrypWaitingResource resource = exchange.poll(timeoutMs, TimeUnit.MILLISECONDS);
            if (resource==null) {
                //TODO we should throw some sort of authentication exception
                throw new IllegalStateException("Timed out waiting for brcypt turn");
            } else {
                return resource;
            }
        } catch (InterruptedException e) {
            throw new IllegalStateException("Bcrypt thread was interrupted", e);
        }
    }



    private static class BcrypWaitingResource implements AutoCloseable {

        private final FairBlockingQueue<BcrypWaitingResource> exchange;
        private final String name;

        private BcrypWaitingResource(FairBlockingQueue<BcrypWaitingResource> exchange, String name) {
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

