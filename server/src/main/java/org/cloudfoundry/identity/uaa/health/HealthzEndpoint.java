package org.cloudfoundry.identity.uaa.health;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;

/**
 * Simple controller that just returns "ok" in a request body for the purposes
 * of monitoring health of the application. It also registers a shutdown hook
 * and returns "stopping" and a 503 when the process is shutting down.
 */
@Controller
public class HealthzEndpoint {
    private static Logger logger = LoggerFactory.getLogger(HealthzEndpoint.class);
    private volatile boolean stopping = false;

    public HealthzEndpoint(
            @Value("${uaa.shutdown.sleep:10000}") final long sleepTime,
            final Runtime runtime) {
        Thread shutdownHook = new Thread(() -> {
            stopping = true;
            logger.warn("Shutdown hook received, future requests to this endpoint will return 503");
            try {
                if (sleepTime > 0) {
                    logger.debug("Healthz is sleeping shutdown thread for " + sleepTime + " ms.");
                    Thread.sleep(sleepTime);
                }
            } catch (InterruptedException e) {
                logger.warn("Shutdown sleep interrupted.", e);
            }
        });
        runtime.addShutdownHook(shutdownHook);
    }

    @RequestMapping("/healthz")
    @ResponseBody
    public String getHealthz(HttpServletResponse response) {
        if (stopping) {
            logger.debug("Received /healthz request during shutdown. Returning 'stopping'");
            response.setStatus(503);
            return "stopping\n";
        } else {
            return "ok\n";
        }
    }

}