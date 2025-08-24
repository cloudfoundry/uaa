/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.test;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

public class TestApplicationEventPublisher<T extends ApplicationEvent> extends TestApplicationEventHandler<T> implements ApplicationEventPublisher {

    public static <K extends ApplicationEvent> TestApplicationEventPublisher<K> forEventClass(Class<K> eventType) {
        return new TestApplicationEventPublisher<>(eventType);
    }

    protected TestApplicationEventPublisher(Class<T> eventType) {
        super(eventType);
    }

    @Override
    public void publishEvent(ApplicationEvent applicationEvent) {
        handleEvent(applicationEvent);
    }

    @Override
    public void publishEvent(Object event) {
        throw new UnsupportedOperationException("not implemented");
    }
}
