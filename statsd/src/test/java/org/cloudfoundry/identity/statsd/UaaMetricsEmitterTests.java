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

import com.timgroup.statsd.ConvenienceMethodProvidingStatsDClient;
import com.timgroup.statsd.StatsDClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.management.MBeanServerConnection;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.times;

public class UaaMetricsEmitterTests {

    private MBeanServerConnection server;
    private StatsDClient statsDClient;
    private UaaMetricsEmitter uaaMetricsEmitter;
    private MBeanMap mBeanMap1;
    private MBeanMap mBeanMap2;
    private Map<String, MBeanMap> mBeanMap3;
    private MBeanMap serverRequestsBeanMap;

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
        mBeanMap2.put("UaaAudit", mBeanMap1);

        serverRequestsBeanMap = new MBeanMap();
        serverRequestsBeanMap.put("globals", globalsJson);
        serverRequestsBeanMap.put("inflight.count", 3l);


        mBeanMap3 = new HashMap();
        mBeanMap3.put("ServerRequests", serverRequestsBeanMap);
    }

    @Test
    public void auditService_metrics_emitted() throws Exception {
        MetricsUtils metricsUtils = Mockito.mock(MetricsUtils.class);
        uaaMetricsEmitter.setMetricsUtils(metricsUtils);
        Mockito.when(metricsUtils.pullUpMap("cloudfoundry.identity", "*", server)).thenReturn((Map)mBeanMap2);
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
    public void requestCount_metrics_emitted() throws Exception {
        MetricsUtils metricsUtils = Mockito.mock(MetricsUtils.class);
        uaaMetricsEmitter.setMetricsUtils(metricsUtils);
        Mockito.when(metricsUtils.pullUpMap("cloudfoundry.identity", "*", server)).thenReturn((Map)mBeanMap3);

        uaaMetricsEmitter.emitGlobalRequestMetrics();
        Mockito.verify(statsDClient).gauge("requests.global.completed.count", 18l);
        Mockito.verify(statsDClient).gauge("requests.global.completed.time", 67l);
        Mockito.verify(statsDClient).gauge("server.inflight.count", 3l);
        Mockito.verify(statsDClient).gauge("requests.global.unhealthy.count", 1l);
        Mockito.verify(statsDClient).gauge("requests.global.unhealthy.time", (long)3.25);
    }

    @Test
    public void auditService_metricValues_areNull() throws Exception {
        mBeanMap1.put("user_authentication_count", null);

        MetricsUtils metricsUtils = Mockito.mock(MetricsUtils.class);
        uaaMetricsEmitter.setMetricsUtils(metricsUtils);
        Mockito.when(metricsUtils.pullUpMap("cloudfoundry.identity", "*", server)).thenReturn((Map)mBeanMap2);
        uaaMetricsEmitter.emitMetrics();
        Mockito.verify(statsDClient).gauge("audit_service.user_not_found_count", 1);
        Mockito.verify(statsDClient, times(6)).gauge(anyString(), anyInt());
    }

    @Test
    public void auditService_Key_isNull () throws Exception {
        mBeanMap2.put("UaaAudit", null);

        MetricsUtils metricsUtils = Mockito.mock(MetricsUtils.class);
        uaaMetricsEmitter.setMetricsUtils(metricsUtils);
        Mockito.when(metricsUtils.pullUpMap("cloudfoundry.identity", "*", server)).thenReturn((Map)mBeanMap2);
        uaaMetricsEmitter.emitMetrics();

        Mockito.verify(statsDClient, times(0)).gauge(anyString(), anyInt());
    }

    public void test(Collection<?> c) {
        Collection<String> cs = null;
        test(cs);
    }

    String globalsJson = "{\n" +
        "   \"lastRequests\":[\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/\",\n" +
        "         \"statusCode\":302,\n" +
        "         \"requestStartTime\":1505967590958,\n" +
        "         \"requestCompleteTime\":1505967590982,\n" +
        "         \"nrOfDatabaseQueries\":1,\n" +
        "         \"databaseQueryTime\":0\n" +
        "      },\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/login\",\n" +
        "         \"statusCode\":200,\n" +
        "         \"requestStartTime\":1505967590991,\n" +
        "         \"requestCompleteTime\":1505967591648,\n" +
        "         \"nrOfDatabaseQueries\":12,\n" +
        "         \"databaseQueryTime\":1\n" +
        "      },\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/\",\n" +
        "         \"statusCode\":302,\n" +
        "         \"requestStartTime\":1505967591913,\n" +
        "         \"requestCompleteTime\":1505967591918,\n" +
        "         \"nrOfDatabaseQueries\":1,\n" +
        "         \"databaseQueryTime\":0\n" +
        "      },\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/login\",\n" +
        "         \"statusCode\":200,\n" +
        "         \"requestStartTime\":1505967591921,\n" +
        "         \"requestCompleteTime\":1505967591977,\n" +
        "         \"nrOfDatabaseQueries\":12,\n" +
        "         \"databaseQueryTime\":0\n" +
        "      },\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/vendor/font-awesome/css/font-awesome.min.css\",\n" +
        "         \"statusCode\":200,\n" +
        "         \"requestStartTime\":1505967591982,\n" +
        "         \"requestCompleteTime\":1505967592031,\n" +
        "         \"nrOfDatabaseQueries\":1,\n" +
        "         \"databaseQueryTime\":0\n" +
        "      }\n" +
        "   ],\n" +
        "   \"detailed\":{\n" +
        "      \"200\":{\n" +
        "         \"count\":14,\n" +
        "         \"averageTime\":74.21428571428572,\n" +
        "         \"intolerableCount\":1,\n" +
        "         \"averageIntolerableTime\":3.25,\n" +
        "         \"databaseQueryCount\":113,\n" +
        "         \"averageDatabaseQueryTime\":0.03539823008849556,\n" +
        "         \"databaseFailedQueryCount\":0,\n" +
        "         \"averageDatabaseFailedQueryTime\":0.0\n" +
        "      },\n" +
        "      \"302\":{\n" +
        "         \"count\":4,\n" +
        "         \"averageTime\":46.0,\n" +
        "         \"intolerableCount\":0,\n" +
        "         \"averageIntolerableTime\":0.0,\n" +
        "         \"databaseQueryCount\":30,\n" +
        "         \"averageDatabaseQueryTime\":0.03333333333333333,\n" +
        "         \"databaseFailedQueryCount\":0,\n" +
        "         \"averageDatabaseFailedQueryTime\":0.0\n" +
        "      }\n" +
        "   },\n" +
        "   \"summary\":{\n" +
        "      \"count\":18,\n" +
        "      \"averageTime\":67.94444444444446,\n" +
        "      \"intolerableCount\":0,\n" +
        "      \"averageIntolerableTime\":0.0,\n" +
        "      \"databaseQueryCount\":143,\n" +
        "      \"averageDatabaseQueryTime\":0.034965034965034954,\n" +
        "      \"databaseFailedQueryCount\":0,\n" +
        "      \"averageDatabaseFailedQueryTime\":0.0\n" +
        "   }\n" +
        "}";
}
