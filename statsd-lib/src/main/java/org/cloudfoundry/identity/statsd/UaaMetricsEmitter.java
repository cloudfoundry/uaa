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

import com.timgroup.statsd.StatsDClient;
import org.cloudfoundry.identity.uaa.metrics.MetricsQueue;
import org.cloudfoundry.identity.uaa.metrics.RequestMetricSummary;
import org.cloudfoundry.identity.uaa.metrics.StatusCodeGroup;
import org.cloudfoundry.identity.uaa.metrics.UaaMetrics;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.util.ReflectionUtils;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanServerConnection;
import javax.management.NotificationEmitter;
import com.sun.management.*;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.reflect.Method;
import java.lang.reflect.UndeclaredThrowableException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Optional.ofNullable;
import static org.springframework.util.ReflectionUtils.findMethod;

public class UaaMetricsEmitter {
    private static final Logger logger = LoggerFactory.getLogger(UaaMetricsEmitter.class);

    private static final RequestMetricSummary MISSING_METRICS = new RequestMetricSummary(0L, 0d, 0L, 0d, 0L, 0d, 0L, 0d);
    private final StatsDClient statsDClient;
    private final MBeanServerConnection server;
    private final MetricsUtils metricsUtils;
    private boolean notificationsEnabled;
    private final ConcurrentMap<String, Long> delta = new ConcurrentHashMap<>();

    public UaaMetricsEmitter(MetricsUtils metricsUtils, StatsDClient statsDClient, MBeanServerConnection server) {
        this.statsDClient = statsDClient;
        this.server = server;
        this.metricsUtils = metricsUtils;
        this.notificationsEnabled = false;
    }

    @Scheduled(fixedRate = 5000, initialDelay = 0)
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
                properties.entrySet()
                        .stream()
                        .filter(e -> e.getValue() != null && e.getValue() instanceof Integer)
                        .forEach(e -> statsDClient.gauge(prefix + e.getKey(), ((Integer) e.getValue()).longValue()));
            }
        }
    }

    @Scheduled(fixedRate = 5000, initialDelay = 1000)
    public void emitGlobalRequestMetrics() throws Exception {
        try {
            UaaMetrics metrics = metricsUtils.getUaaMetrics(server);
            emitGlobalRequestMetrics(metrics);
            emitGlobalServerStats(metrics);
        } catch (Exception x) {
            throwIfOtherThanNotFound(x);
        }
    }


    @Scheduled(fixedRate = 5000, initialDelay = 1000)
    public void emitUrlGroupRequestMetrics() throws Exception {
        try {
            UaaMetrics metrics = metricsUtils.getUaaMetrics(server);
            emitUrlGroupRequestMetrics(metrics);
        } catch (Exception x) {
            throwIfOtherThanNotFound(x);
        }
    }

    private void emitUrlGroupRequestMetrics(UaaMetrics metrics) {
        Map<String, String> perUrlMetrics = metrics.getSummary();
        String prefix = "requests.%s.";
        for (String key : perUrlMetrics.keySet()) {
            String prefixName = key.startsWith("/") ? key.substring(1) : key;
            MetricsQueue metric = JsonUtils.readValue(perUrlMetrics.get(key), MetricsQueue.class);
            RequestMetricSummary metricTotals = metric.getTotals();
            statsDClient.gauge((prefix + "completed.count").formatted(prefixName), metricTotals.getCount());
            statsDClient.gauge((prefix + "completed.time").formatted(prefixName), (long) metricTotals.getAverageTime());
        }
    }

    public void emitGlobalServerStats(UaaMetrics metrics) {
        //server statistics
        statsDClient.gauge("server.inflight.count", metrics.getInflightCount());
        statsDClient.gauge("server.up.time", metrics.getUpTime());
        statsDClient.gauge("server.idle.time", metrics.getIdleTime());
    }

    public void emitGlobalRequestMetrics(UaaMetrics metrics) {
        //global request statistics
        MetricsQueue globals = JsonUtils.readValue(metrics.getGlobals(), MetricsQueue.class);

        String prefix = "requests.global.";
        RequestMetricSummary totals = globals.getTotals();
        statsDClient.gauge(prefix + "completed.time", (long) totals.getAverageTime());
        statsDClient.count(prefix + "completed.count", getMetricDelta(prefix + "completed.count", totals.getCount()));
        statsDClient.count(prefix + "unhealthy.count", getMetricDelta(prefix + "unhealthy.count", totals.getIntolerableCount()));
        statsDClient.gauge(prefix + "unhealthy.time", (long) totals.getAverageIntolerableTime());
        //status codes
        for (StatusCodeGroup family : StatusCodeGroup.values()) {
            RequestMetricSummary summary = ofNullable(globals.getDetailed().get(family)).orElse(MISSING_METRICS);
            String aspect = prefix + "status_" + family.getName() + ".count";
            statsDClient.count(aspect, getMetricDelta(aspect, summary.getCount()));
        }
        //database metrics
        prefix = "database.global.";
        statsDClient.gauge(prefix + "completed.time", (long) totals.getAverageDatabaseQueryTime());
        statsDClient.count(prefix + "completed.count", getMetricDelta(prefix + "completed.count", totals.getDatabaseQueryCount()));
        statsDClient.count(prefix + "unhealthy.count", getMetricDelta(prefix + "unhealthy.count", totals.getDatabaseIntolerableQueryCount()));
        statsDClient.gauge(prefix + "unhealthy.time", (long) totals.getAverageDatabaseIntolerableQueryTime());
    }

    @Scheduled(fixedRate = 5000, initialDelay = 2000)
    public void emitVmVitals() {
        OperatingSystemMXBean mbean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        String prefix = "vitals.vm.";
        statsDClient.gauge(prefix + "cpu.count", mbean.getAvailableProcessors());
        statsDClient.gauge(prefix + "cpu.load", (long) (mbean.getSystemLoadAverage() * 100));
        statsDClient.gauge(prefix + "memory.total", mbean.getTotalPhysicalMemorySize());
        statsDClient.gauge(prefix + "memory.committed", mbean.getCommittedVirtualMemorySize());
        statsDClient.gauge(prefix + "memory.free", mbean.getFreePhysicalMemorySize());
    }

    @Scheduled(fixedRate = 5000, initialDelay = 3000)
    public void emitJvmVitals() {
        OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        ThreadMXBean threadBean = (ThreadMXBean) ManagementFactory.getThreadMXBean();
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        String prefix = "vitals.jvm.";
        statsDClient.gauge(prefix + "cpu.load", (long) (((Number) osBean.getProcessCpuLoad()).doubleValue() * 100));
        statsDClient.gauge(prefix + "thread.count", threadBean.getThreadCount());
        Map<String, MemoryUsage> memory = new HashMap<>();
        memory.put("heap", memoryBean.getHeapMemoryUsage());
        memory.put("non-heap", memoryBean.getNonHeapMemoryUsage());
        memory.forEach((key, value) -> {
            statsDClient.gauge(prefix + key + ".init", value.getInit());
            statsDClient.gauge(prefix + key + ".committed", value.getCommitted());
            statsDClient.gauge(prefix + key + ".used", value.getUsed());
            statsDClient.gauge(prefix + key + ".max", value.getMax());
        });

    }

    public void throwIfOtherThanNotFound(Exception x) throws Exception {
        //compiler will not let me catch InstanceNotFoundException
        //because its hidden behind the proxy creator
        if (x instanceof UndeclaredThrowableException && x.getCause() instanceof InstanceNotFoundException) {
            //normal - the statsd server may have
            //started before the UAA
            logger.info("Could not find UaaMetrics object on MBean server. Please deploy UAA in the same JVM.");
        } else {
            throw x;
        }
    }

    public Number getValueFromBean(Object mbean, String getter) {
        Method method = findMethod(mbean.getClass(), getter);
        if (method != null) {
            boolean original = method.isAccessible();
            method.setAccessible(true);
            try {
                return (Number) ReflectionUtils.invokeMethod(method, mbean);
            } catch (Exception e) {
                logger.debug("Unable to invoke metric", e);
            } finally {
                method.setAccessible(original);
            }

        }
        return  null;
    }

    public Object getValueFromMap(Map<String, ?> map, String path) throws Exception {
        MapWrapper wrapper = new MapWrapper(map);
        return wrapper.get(path);
    }

    public void enableNotification() {
        try {
            logger.debug("Trying to enable notification");
            NotificationEmitter emitter = metricsUtils.getUaaMetricsSubscriber(server);
            emitter.addNotificationListener((notification, handback) -> {
                String key = notification.getType();
                String prefix = key.startsWith("/") ? key.substring(1) : key;
                statsDClient.time("requests.%s.latency".formatted(prefix), (Long) notification.getSource());
            }, null, null);
            notificationsEnabled = true;
        } catch (Exception instanceNotFound) {
            try {
                throwIfOtherThanNotFound(instanceNotFound);
            } catch (Exception e) {
                logger.info("Unable to create server request metric bean", e);
            }
        }
    }

    public long getMetricDelta(String name, long gaugeValue) {
        long result = gaugeValue;
        Long data = delta.get(name);
        delta.put(name, gaugeValue);
        if (data != null) {
            result = gaugeValue - data;
        }
        return result;

    }

    public boolean isNotificationEnabled() {
        return notificationsEnabled;
    }

    class MapWrapper {

        private final SpelExpressionParser parser;

        private final StandardEvaluationContext context;

        private final Map<String, ?> target;

        public MapWrapper(Map<String, ?> target) {
            this.target = target;
            context = new StandardEvaluationContext();
            context.addPropertyAccessor(new MapAccessor());
            parser = new SpelExpressionParser();
        }

        public Object get(String expression) {
            return get(expression, Object.class);
        }

        public <T> T get(String expression, Class<T> type) {
            return parser.parseExpression(expression).getValue(context, target, type);
        }

        @Override
        public String toString() {
            return target.toString();
        }

    }
}
