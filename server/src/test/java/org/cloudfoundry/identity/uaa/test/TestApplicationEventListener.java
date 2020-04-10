
package org.cloudfoundry.identity.uaa.test;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

public class TestApplicationEventListener<T extends ApplicationEvent> extends TestApplicationEventHandler<T> implements ApplicationListener<T> {

    public static <K extends ApplicationEvent> TestApplicationEventListener<K> forEventClass(Class<K> eventType) {
        return new TestApplicationEventListener<K>(eventType) {};
    }

    protected TestApplicationEventListener(Class<T> eventType) {
        super(eventType);
    }

    @Override
    public void onApplicationEvent(T event) {
        handleEvent(event);
    }
}
