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

import com.timgroup.statsd.StatsDClient;
import org.cloudfoundry.identity.uaa.metrics.MetricsQueue;
import org.cloudfoundry.identity.uaa.metrics.StatusCodeGroup;
import org.cloudfoundry.identity.uaa.metrics.RequestMetricSummary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.scheduling.annotation.Scheduled;

import javax.management.MBeanServerConnection;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Optional.ofNullable;

public class UaaMetricsEmitter {
    private final StatsDClient statsDClient;
    private final MBeanServerConnection server;
    @Autowired
    private MetricsUtils metricsUtils;
    private RequestMetricSummary MISSING_METRICS = new RequestMetricSummary(0l, 0d, 0l, 0d, 0l, 0d, 0l, 0d);

    public UaaMetricsEmitter(StatsDClient statsDClient, MBeanServerConnection server) {
        this.statsDClient = statsDClient;
        this.server = server;
    }

    @Scheduled(fixedRate = 5000)
    public void emitMetrics() throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        Map<String, ?> spring = metricsUtils.pullUpMap("cloudfoundry.identity", "*", server);

        if (spring != null) {
            result.put("audit_service", getValueFromMap(spring, "#this['UaaAudit']"));
        }
        for (Map.Entry entry : result.entrySet()) {
            String prefix = entry.getKey() + ".";
            MBeanMap properties = (MBeanMap) entry.getValue();
            if (properties != null) {
                properties.entrySet().stream().filter(e -> e.getValue() != null && e.getValue() instanceof Integer).forEach(e -> statsDClient.gauge(prefix+e.getKey(), (Integer) e.getValue()));
            }
        }
    }

    @Scheduled(fixedRate = 5000)
    public void emitGlobalRequestMetrics() throws Exception {
        Map<String, ?> mebeans = metricsUtils.pullUpMap("cloudfoundry.identity", "*", server);
        if (mebeans != null) {
            MBeanMap uaaMetricsMap = (MBeanMap) getValueFromMap(mebeans, "#this['ServerRequests']");
            if (uaaMetricsMap == null) {
                return;
            }
            //global request statistics
            if (uaaMetricsMap.get("globals") != null){
                String json = (String) uaaMetricsMap.get("globals");
                if (json != null) {
                    MetricsQueue globals = JsonUtils.readValue(json, MetricsQueue.class);
                    String prefix = "requests.global.";
                    RequestMetricSummary totals = globals.getTotals();
                    statsDClient.gauge(prefix + "completed.time", (long) totals.getAverageTime());
                    statsDClient.gauge(prefix + "completed.count", totals.getCount());
                    //unhealthy
                    statsDClient.gauge(prefix + "unhealthy.count", totals.getIntolerableCount());
                    statsDClient.gauge(prefix + "unhealthy.time", (long) totals.getAverageIntolerableTime());
                    //status codes
                    for (StatusCodeGroup family : StatusCodeGroup.values()) {
                        RequestMetricSummary summary =
                            ofNullable(globals.getDetailed().get(family))
                                .orElse(MISSING_METRICS);

                        statsDClient.gauge(prefix + "status_"+family.getName()+".count", summary.getCount());
                    }

                }
            }
            //server statistics
            if (uaaMetricsMap.get("inflight.count") != null){
                long value = (long)uaaMetricsMap.get("inflight.count");
                statsDClient.gauge("server.inflight.count", value);
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
