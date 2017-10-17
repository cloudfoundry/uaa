package org.cloudfoundry.identity.uaa.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.web.session.HttpSessionCreatedEvent;

public class SessionIdleTimeoutSetter implements ApplicationListener<HttpSessionCreatedEvent> {

    private static Log logger = LogFactory.getLog(SessionIdleTimeoutSetter.class);

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