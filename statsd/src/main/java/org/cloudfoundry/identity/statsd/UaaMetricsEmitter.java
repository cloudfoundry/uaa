package org.cloudfoundry.identity.statsd;

import com.timgroup.statsd.StatsDClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.scheduling.annotation.Scheduled;

import javax.management.MBeanServerConnection;
import java.util.LinkedHashMap;
import java.util.Map;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class UaaMetricsEmitter {

    private final StatsDClient statsDClient;
    private final MBeanServerConnection server;
    @Autowired
    private MetricsUtils metricsUtils;

    public UaaMetricsEmitter(StatsDClient statsDClient, MBeanServerConnection server) {
        this.statsDClient = statsDClient;
        this.server = server;
    }

    @Scheduled(fixedRate = 5000)
    public void emitMetrics() throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        Map<String, ?> spring = metricsUtils.pullUpMap("spring.application", "*", server);

        if (spring != null) {
            result.put("audit_service", getValueFromMap(spring, "#this['LoggingAuditService']?.loggingAuditService"));
        }
        for (Map.Entry entry : result.entrySet()) {
            String prefix = entry.getKey() + ".";
            MBeanMap properties = (MBeanMap) entry.getValue();
            if (properties != null) {
                properties.entrySet().stream().filter(e -> e.getValue() != null && e.getValue() instanceof Integer).forEach(e -> statsDClient.gauge(prefix+e.getKey(), (Integer) e.getValue()));
            }
        }
    }

    public void setMetricsUtils(MetricsUtils metricsUtils) {
        this.metricsUtils = metricsUtils;
    }

    public Object getValueFromMap(Map<String, ?> map, String path) throws Exception {
        MapWrapper wrapper = new MapWrapper(map);
        return wrapper.get(path);
    }

    class MapWrapper {

        private final SpelExpressionParser parser;

        private final StandardEvaluationContext context;

        private final Map<String, ?> target;

        public MapWrapper(Map<String, ?> target) throws Exception {
            this.target = target;
            context = new StandardEvaluationContext();
            context.addPropertyAccessor(new MapAccessor());
            parser = new SpelExpressionParser();
        }

        public Object get(String expression) throws Exception {
            return get(expression, Object.class);
        }

        public <T> T get(String expression, Class<T> type) throws Exception {
            return parser.parseExpression(expression).getValue(context, target, type);
        }

        @Override
        public String toString() {
            return target.toString();
        }

    }
}
