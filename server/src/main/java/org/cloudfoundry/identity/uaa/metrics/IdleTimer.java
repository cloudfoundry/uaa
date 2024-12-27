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

package org.cloudfoundry.identity.uaa.metrics;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;

/**
 * Calculates the time that a server is idle (no requests processing)
 * The idle time calculator starts as soon as this object is created.
 */
public class IdleTimer {

    TimeService timeService = new TimeServiceImpl();

    private long inflightRequests;
    private long idleTime;

    private long lastIdleStart = timeService.getCurrentTimeMillis();
    private final long startTime = timeService.getCurrentTimeMillis();
    private long requestCount;

    public synchronized void endRequest() {
        switch ((int) --inflightRequests) {
            case 0:
                lastIdleStart = timeService.getCurrentTimeMillis();
                break;
            case -1:
                throw new IllegalStateException("Illegal end request invocation, no request in flight");
            default:
                break;
        }
        requestCount++;
    }

    public synchronized void startRequest() {
        if ((int) ++inflightRequests == 1) {
            idleTime += timeService.getCurrentTimeMillis() - lastIdleStart;
        }
    }


    public long getInflightRequests() {
        return inflightRequests;
    }

    public synchronized long getIdleTime() {
        if (inflightRequests == 0) {
            return (timeService.getCurrentTimeMillis() - lastIdleStart) + idleTime;
        } else {
            return idleTime;
        }
    }

    public long getRunTime() {
        return timeService.getCurrentTimeMillis() - startTime;
    }

    protected long getRequestCount() {
        return requestCount;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }
}
