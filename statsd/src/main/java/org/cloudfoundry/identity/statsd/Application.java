/*******************************************************************************
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
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import java.lang.management.ManagementFactory;
import java.util.Calendar;
import java.util.Date;

@SpringBootApplication
@EnableScheduling
public class Application extends SpringBootServletInitializer implements SchedulingConfigurer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(Application.class);
    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(Application.class);
    }

    @Bean
    public UaaMetricsEmitter statsDClientWrapper(MetricsUtils utils, StatsDClient client) {
        return new UaaMetricsEmitter(utils, client, ManagementFactory.getPlatformMBeanServer());
    }

    @Bean
    public StatsDClient statsDClient() {
        return new NonBlockingStatsDClient("uaa", "localhost", 8125);
    }

    @Bean
    public MetricsUtils metricsUtils() {
        return new MetricsUtils();
    }

    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        taskRegistrar.addTriggerTask(() -> statsDClientWrapper(metricsUtils(), statsDClient()).enableNotification(),
                triggerContext -> {
                    if (statsDClientWrapper(metricsUtils(), statsDClient()).isNotificationEnabled()) {
                        return null;
                    } else {
                        Calendar calendar = Calendar.getInstance();
                        if (triggerContext.lastCompletionTime() != null) {
                            calendar.setTime(triggerContext.lastCompletionTime());
                        } else {
                            calendar.setTime(new Date());
                        }
                        calendar.add(Calendar.SECOND, 5);
                        return calendar.getTime();
                    }
                });
    }
}
