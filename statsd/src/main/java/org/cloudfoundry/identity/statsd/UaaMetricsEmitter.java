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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.metrics.MetricsQueue;
import org.cloudfoundry.identity.uaa.metrics.RequestMetricSummary;
import org.cloudfoundry.identity.uaa.metrics.StatusCodeGroup;
import org.cloudfoundry.identity.uaa.metrics.UaaMetrics;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.util.ReflectionUtils;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanServerConnection;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.reflect.Method;
import java.lang.reflect.UndeclaredThrowableException;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Optional.ofNullable;
import static org.springframework.util.ReflectionUtils.*;

public class UaaMetricsEmitter {
    private static Log logger = LogFactory.getLog(UaaMetricsEmitter.class);

    private static final RequestMetricSummary MISSING_METRICS = new RequestMetricSummary(0l, 0d, 0l, 0d, 0l, 0d, 0l, 0d);
    private final StatsDClient statsDClient;
    private final MBeanServerConnection server;
    private final MetricsUtils metricsUtils;

    public UaaMetricsEmitter(MetricsUtils metricsUtils, StatsDClient statsDClient, MBeanServerConnection server) {
        this.statsDClient = statsDClient;
        this.server = server;
        this.metricsUtils = metricsUtils;
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
                properties.entrySet().stream().filter(e -> e.getValue() != null && e.getValue() instanceof Integer).forEach(e -> statsDClient.gauge(prefix+e.getKey(), (Integer) e.getValue()));
            }
        }
    }

    @Scheduled(fixedRate = 5000, initialDelay = 1500)
    public void emitGlobalRequestMetrics() throws Exception {
        try {
            UaaMetrics metrics = metricsUtils.getUaaMetrics(server);
            emitGlobalRequestMetrics(metrics);
            emitGlobalServerStats(metrics);
        } catch (Exception x) {
            throwIfOtherThanNotFound(x);
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
        statsDClient.gauge(prefix + "completed.count", totals.getCount());
        statsDClient.gauge(prefix + "unhealthy.count", totals.getIntolerableCount());
        statsDClient.gauge(prefix + "unhealthy.time", (long) totals.getAverageIntolerableTime());
        //status codes
        for (StatusCodeGroup family : StatusCodeGroup.values()) {
            RequestMetricSummary summary = ofNullable(globals.getDetailed().get(family)).orElse(MISSING_METRICS);
            statsDClient.gauge(prefix + "status_"+family.getName()+".count", summary.getCount());
        }
        //database metrics
        prefix = "database.global.";
        statsDClient.gauge(prefix + "completed.time", (long) totals.getAverageDatabaseQueryTime());
        statsDClient.gauge(prefix + "completed.count", totals.getDatabaseQueryCount());
        statsDClient.gauge(prefix + "unhealthy.count", totals.getDatabaseFailedQueryCount());
        statsDClient.gauge(prefix + "unhealthy.time", (long) totals.getAverageDatabaseFailedQueryTime());
    }

    @Scheduled(fixedRate = 5000, initialDelay = 3000)
    public void emitVitals() throws Exception {
        OperatingSystemMXBean mbean = ManagementFactory.getOperatingSystemMXBean();
        emitVmVitals(mbean);
    }

    public void emitVmVitals(OperatingSystemMXBean mbean) {
        String prefix = "vitals.vm.";
        statsDClient.gauge(prefix + "cpu.count", mbean.getAvailableProcessors());
        statsDClient.gauge(prefix + "cpu.load", (long)(mbean.getSystemLoadAverage()*100));
        invokeIfPresent(prefix + "memory.total", mbean, "getTotalPhysicalMemorySize");
        invokeIfPresent(prefix + "memory.committed", mbean, "getCommittedVirtualMemorySize");
        invokeIfPresent(prefix + "memory.free", mbean, "getFreePhysicalMemorySize");
    }

    public void invokeIfPresent(String metric, Object mbean, String getter) {
        Object value = getValueFromBean(mbean, getter);
        long v = (long)ofNullable(value).orElse(-1l);;
        if (v >= 0) {
            statsDClient.gauge(metric, v);
        }
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

    public Object getValueFromBean(Object mbean, String getter) {
        Method method = findMethod(mbean.getClass(), getter);
        if (method != null) {
            boolean original = method.isAccessible();
            method.setAccessible(true);
            try {
                return ReflectionUtils.invokeMethod(method, mbean);
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
