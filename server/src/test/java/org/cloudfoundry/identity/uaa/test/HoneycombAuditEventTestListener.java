package org.cloudfoundry.identity.uaa.test;

import io.honeycomb.libhoney.EventFactory;
import org.springframework.context.ApplicationEvent;

public class HoneycombAuditEventTestListener<T extends ApplicationEvent> extends TestApplicationEventListener<T> {
    public static String testRunning;

    private EventFactory honeycombEventFactory;

    public static <K extends ApplicationEvent> HoneycombAuditEventTestListener<K> forEventClass(Class<K> eventType) {
        return new HoneycombAuditEventTestListener<K>(eventType);
    }

    protected HoneycombAuditEventTestListener(Class<T> eventType) {
        super(eventType);
    }

    public EventFactory getHoneycombEventFactory() {
        return honeycombEventFactory;
    }

    public void setHoneycombEventFactory(EventFactory honeycombEventFactory) {
        this.honeycombEventFactory = honeycombEventFactory;
    }

    @Override
    protected void handleEvent(ApplicationEvent applicationEvent) {
        super.handleEvent(applicationEvent);

        this.events.removeIf(event -> {
            honeycombEventFactory.createEvent()
                    .addField("auditEvent", event.getClass().getSimpleName())
                    .addField("eventSource", event.toString())
                    .addField("testName", testRunning)
                    .send();
            return true;
        });
    }
}
