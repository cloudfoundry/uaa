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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;

@Configuration
@EnableScheduling
public class StatsdConfiguration {

    @Bean
    public UaaMetricsEmitter statsDClientWrapper() {
        return new UaaMetricsEmitter(
                new MetricsUtils(),
                new NonBlockingStatsDClient("uaa", "localhost", 8125),
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
                    return triggerContext.lastCompletionTime() != null
                            ? getFiveSecondsFrom(triggerContext.lastCompletionTime())
                            : getFiveSecondsFrom(new Date());
                });
    }

    private Instant getFiveSecondsFrom(Date date) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.SECOND, 5);
        return calendar.getTime().toInstant();
    }
}
