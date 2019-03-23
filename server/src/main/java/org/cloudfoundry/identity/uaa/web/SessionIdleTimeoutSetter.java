package org.cloudfoundry.identity.uaa.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.web.session.HttpSessionCreatedEvent;

public class SessionIdleTimeoutSetter implements ApplicationListener<HttpSessionCreatedEvent> {

    private static Logger logger = LoggerFactory.getLogger(SessionIdleTimeoutSetter.class);

    private int timeout = 30 * 60;

    @Override
    public void onApplicationEvent(HttpSessionCreatedEvent event) {
        logger.debug("Setting session timeout["+event.getSession().getId()+"] to :"+timeout);
        event.getSession().setMaxInactiveInterval(timeout);
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getTimeout() {
        return timeout;
    }
}