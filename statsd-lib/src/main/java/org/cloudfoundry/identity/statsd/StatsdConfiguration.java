/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.statsd;

import com.timgroup.statsd.NonBlockingStatsDClient;
import com.timgroup.statsd.StatsDClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Configuration
@EnableScheduling
public class StatsdConfiguration {

    @Bean
    public StatsDClient statsDClient() {
        return new NonBlockingStatsDClient("uaa", "localhost", 8125);
    }

    @Bean
    public UaaMetricsEmitter statsDClientWrapper(StatsDClient statsDClient) {
        return new UaaMetricsEmitter(
                new MetricsUtils(),
                statsDClient,
                ManagementFactory.getPlatformMBeanServer());
    }

    @Bean
    public SchedulingConfigurer schedulingConfigurer(UaaMetricsEmitter uaaMetricsEmitter) {
        return taskRegistrar -> taskRegistrar.addTriggerTask(
                uaaMetricsEmitter::enableNotification,
                triggerContext -> {
                    if (uaaMetricsEmitter.isNotificationEnabled()) {
                        return null;
                    }
                    Instant lastCompletion = triggerContext.lastCompletion();
                    return getFiveSecondsFrom(lastCompletion != null ? lastCompletion : Instant.now());
                });
    }

    private Instant getFiveSecondsFrom(Instant instant) {
        return instant.plus(5, ChronoUnit.SECONDS);
    }
}
