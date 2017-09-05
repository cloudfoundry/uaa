package org.cloudfoundry.identity.statsd;

import com.timgroup.statsd.ConvenienceMethodProvidingStatsDClient;
import com.timgroup.statsd.StatsDClient;
import org.cloudfoundry.identity.statsd.MBeanMap;
import org.cloudfoundry.identity.statsd.MetricsUtils;
import org.cloudfoundry.identity.statsd.UaaMetricsEmitter;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.verification.VerificationMode;

import javax.management.MBeanServerConnection;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

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
public class UaaMetricsEmitterTests {

    private MBeanServerConnection server;
    private StatsDClient statsDClient;
    private UaaMetricsEmitter uaaMetricsEmitter;
    private MBeanMap mBeanMap1;
    private MBeanMap mBeanMap2;
    private Map<String, MBeanMap> mBeanMap3;

    @Before
    public void setUp() {
        server = Mockito.mock(MBeanServerConnection.class);
        statsDClient = Mockito.mock(ConvenienceMethodProvidingStatsDClient.class);
        uaaMetricsEmitter = new UaaMetricsEmitter(statsDClient, server);

        mBeanMap1 = new MBeanMap();
        mBeanMap1.put("user_authentication_count", 3);
        mBeanMap1.put("user_not_found_count", 1);
        mBeanMap1.put("principal_authentication_failure_count", 4);
        mBeanMap1.put("principal_not_found_count", 5);
        mBeanMap1.put("user_authentication_failure_count", 6);
        mBeanMap1.put("client_authentication_count", 7);
        mBeanMap1.put("client_authentication_failure_count", 42);

        mBeanMap2 = new MBeanMap();
        mBeanMap2.put("loggingAuditService", mBeanMap1);

        mBeanMap3 = new HashMap();
        mBeanMap3.put("LoggingAuditService", mBeanMap2);
    }

    @Test
    public void auditService_metrics_emitted() throws Exception {
        MetricsUtils metricsUtils = Mockito.mock(MetricsUtils.class);
        uaaMetricsEmitter.setMetricsUtils(metricsUtils);
        Mockito.when(metricsUtils.pullUpMap("spring.application", "*", server)).thenReturn((Map)mBeanMap3);
        uaaMetricsEmitter.emitMetrics();
        Mockito.verify(statsDClient).gauge("audit_service.user_authentication_count", 3);
        Mockito.verify(statsDClient).gauge("audit_service.user_not_found_count", 1);
        Mockito.verify(statsDClient).gauge("audit_service.principal_authentication_failure_count", 4);
        Mockito.verify(statsDClient).gauge("audit_service.principal_not_found_count", 5);
        Mockito.verify(statsDClient).gauge("audit_service.user_authentication_failure_count", 6);
        Mockito.verify(statsDClient).gauge("audit_service.client_authentication_count", 7);
        Mockito.verify(statsDClient).gauge("audit_service.client_authentication_failure_count", 42);
    }

    @Test
    public void auditService_metricValues_areNull() throws Exception {
        mBeanMap1.put("user_authentication_count", null);

        MetricsUtils metricsUtils = Mockito.mock(MetricsUtils.class);
        uaaMetricsEmitter.setMetricsUtils(metricsUtils);
        Mockito.when(metricsUtils.pullUpMap("spring.application", "*", server)).thenReturn((Map)mBeanMap3);
        uaaMetricsEmitter.emitMetrics();
        Mockito.verify(statsDClient).gauge("audit_service.user_not_found_count", 1);
        Mockito.verify(statsDClient, times(6)).gauge(anyString(), anyInt());
    }

    @Test
    public void auditService_Key_isNull () throws Exception {
        mBeanMap3.put("LoggingAuditService", null);

        MetricsUtils metricsUtils = Mockito.mock(MetricsUtils.class);
        uaaMetricsEmitter.setMetricsUtils(metricsUtils);
        Mockito.when(metricsUtils.pullUpMap("spring.application", "*", server)).thenReturn((Map)mBeanMap3);
        uaaMetricsEmitter.emitMetrics();

        Mockito.verify(statsDClient, times(0)).gauge(anyString(), anyInt());
    }

    public void test(Collection<?> c) {
        Collection<String> cs = null;
        test(cs);
    }
}
