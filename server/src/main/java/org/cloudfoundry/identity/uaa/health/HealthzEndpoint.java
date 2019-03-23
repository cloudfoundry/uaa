/*******************************************************************************
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

package org.cloudfoundry.identity.uaa.health;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;

/**
 * Simple controller that just returns "ok" in a request body for the purposes
 * of monitoring health of the application. It also registers a shutdown hook
 * and returns "stopping" and a 503 when the process is shutting down.
 *
 */
@Controller
public class HealthzEndpoint {
    private static Logger logger = LoggerFactory.getLogger(HealthzEndpoint.class);
    private volatile boolean stopping = false;
    private final Thread shutdownhook;
    private final long sleepTime;

    public HealthzEndpoint(long sleepTime) {
        this.sleepTime = sleepTime;
        shutdownhook = new Thread(() -> {
            stopping = true;
            logger.warn("Shutdown hook received, future requests to this endpoint will return 503");
            try {
                if (sleepTime>0) {
                    logger.debug("Healthz is sleeping shutdown thread for "+sleepTime+" ms.");
                    Thread.sleep(sleepTime);
                }
            } catch (InterruptedException e) {
                logger.warn("Shutdown sleep interrupted.", e);
            }
        });
        Runtime.getRuntime().addShutdownHook(shutdownhook);
    }

    @RequestMapping("/healthz")
    @ResponseBody
    public String getHealthz(HttpServletResponse response) throws Exception {
        if (stopping) {
            logger.debug("Received /healthz request during shutdown. Returning 'stopping'");
            response.setStatus(503);
            return "stopping\n";
        } else {
            return "ok\n";
        }
    }

    public long getSleepTime() {
        return sleepTime;
    }
}