
package org.cloudfoundry.identity.uaa.test;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

public class TestApplicationEventPublisher<T extends ApplicationEvent> extends TestApplicationEventHandler<T> implements ApplicationEventPublisher {

    public static <K extends ApplicationEvent> TestApplicationEventPublisher<K> forEventClass(Class<K> eventType) {
        return new TestApplicationEventPublisher<K>(eventType);
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
