package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.catalina.Container;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Server;
import org.apache.catalina.Service;

import java.util.function.Predicate;
import java.util.stream.Stream;

public class UaaStartupFailureListener implements LifecycleListener {

    private final Predicate<Container> containerFailed = container -> {
        if (container.getState() != LifecycleState.STARTED) {
            return true;
        }

        return Stream.of(container.findChildren()).anyMatch(this.containerFailed);
    };

    @Override
    public void lifecycleEvent(LifecycleEvent event) {
        String eventType = event.getType();
        Lifecycle lifecycle = event.getLifecycle();

        if (lifecycle instanceof Server server && eventType.equals(Lifecycle.AFTER_START_EVENT)) {

            if (Stream.of(server.findServices()).map(Service::getContainer).anyMatch(containerFailed)) {
                try {
                    server.stop();
                    server.destroy();
                } catch (LifecycleException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}
