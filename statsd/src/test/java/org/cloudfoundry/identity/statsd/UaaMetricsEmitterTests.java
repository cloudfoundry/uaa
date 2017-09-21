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
        Mockito.verify(statsDClient).gauge("requests.global.completed.count", 3087l);
        Mockito.verify(statsDClient).gauge("requests.global.completed.time", 29l);
        Mockito.verify(statsDClient).gauge("server.inflight.count", 3l);
        Mockito.verify(statsDClient).gauge("requests.global.unhealthy.count", 1l);
        Mockito.verify(statsDClient).gauge("requests.global.unhealthy.time", 4318l);
        Mockito.verify(statsDClient).gauge("requests.global.status_1xx.count", 0l);
        Mockito.verify(statsDClient).gauge("requests.global.status_2xx.count", 2148l);
        Mockito.verify(statsDClient).gauge("requests.global.status_3xx.count", 763l);
        Mockito.verify(statsDClient).gauge("requests.global.status_4xx.count", 175l);
        Mockito.verify(statsDClient).gauge("requests.global.status_5xx.count", 1l);
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
        "         \"requestStartTime\":1506021406240,\n" +
        "         \"requestCompleteTime\":1506021406260,\n" +
        "         \"nrOfDatabaseQueries\":1,\n" +
        "         \"databaseQueryTime\":0\n" +
        "      },\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/login\",\n" +
        "         \"statusCode\":200,\n" +
        "         \"requestStartTime\":1506021406265,\n" +
        "         \"requestCompleteTime\":1506021406970,\n" +
        "         \"nrOfDatabaseQueries\":12,\n" +
        "         \"databaseQueryTime\":0\n" +
        "      },\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/\",\n" +
        "         \"statusCode\":302,\n" +
        "         \"requestStartTime\":1506021407210,\n" +
        "         \"requestCompleteTime\":1506021407216,\n" +
        "         \"nrOfDatabaseQueries\":1,\n" +
        "         \"databaseQueryTime\":1\n" +
        "      },\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/login\",\n" +
        "         \"statusCode\":200,\n" +
        "         \"requestStartTime\":1506021407224,\n" +
        "         \"requestCompleteTime\":1506021407284,\n" +
        "         \"nrOfDatabaseQueries\":12,\n" +
        "         \"databaseQueryTime\":0\n" +
        "      },\n" +
        "      {\n" +
        "         \"uri\":\"/uaa/resources/oss/stylesheets/application.css\",\n" +
        "         \"statusCode\":304,\n" +
        "         \"requestStartTime\":1506021407293,\n" +
        "         \"requestCompleteTime\":1506021407331,\n" +
        "         \"nrOfDatabaseQueries\":1,\n" +
        "         \"databaseQueryTime\":0\n" +
        "      }\n" +
        "   ],\n" +
        "   \"detailed\":{\n" +
        "      \"SERVER_ERROR\":{\n" +
        "         \"count\":1,\n" +
        "         \"averageTime\":87.0,\n" +
        "         \"intolerableCount\":0,\n" +
        "         \"averageIntolerableTime\":0.0,\n" +
        "         \"databaseQueryCount\":13,\n" +
        "         \"averageDatabaseQueryTime\":0.0,\n" +
        "         \"databaseFailedQueryCount\":0,\n" +
        "         \"averageDatabaseFailedQueryTime\":0.0\n" +
        "      },\n" +
        "      \"REDIRECT\":{\n" +
        "         \"count\":763,\n" +
        "         \"averageTime\":35.86107470511138,\n" +
        "         \"intolerableCount\":1,\n" +
        "         \"averageIntolerableTime\":4318.0,\n" +
        "         \"databaseQueryCount\":5428,\n" +
        "         \"averageDatabaseQueryTime\":0.028002947678703018,\n" +
        "         \"databaseFailedQueryCount\":188,\n" +
        "         \"averageDatabaseFailedQueryTime\":0.047872340425531915\n" +
        "      },\n" +
        "      \"SUCCESS\":{\n" +
        "         \"count\":2148,\n" +
        "         \"averageTime\":28.867318435754207,\n" +
        "         \"intolerableCount\":0,\n" +
        "         \"averageIntolerableTime\":0.0,\n" +
        "         \"databaseQueryCount\":77513,\n" +
        "         \"averageDatabaseQueryTime\":0.0341362094100345,\n" +
        "         \"databaseFailedQueryCount\":17327,\n" +
        "         \"averageDatabaseFailedQueryTime\":0.057136261326253886\n" +
        "      },\n" +
        "      \"CLIENT_ERROR\":{\n" +
        "         \"count\":175,\n" +
        "         \"averageTime\":15.097142857142877,\n" +
        "         \"intolerableCount\":0,\n" +
        "         \"averageIntolerableTime\":0.0,\n" +
        "         \"databaseQueryCount\":843,\n" +
        "         \"averageDatabaseQueryTime\":0.021352313167259794,\n" +
        "         \"databaseFailedQueryCount\":34,\n" +
        "         \"averageDatabaseFailedQueryTime\":0.058823529411764705\n" +
        "      }\n" +
        "   },\n" +
        "   \"summary\":{\n" +
        "      \"count\":3087,\n" +
        "      \"averageTime\":29.834143181081966,\n" +
        "      \"intolerableCount\":1,\n" +
        "      \"averageIntolerableTime\":4318.0,\n" +
        "      \"databaseQueryCount\":83797,\n" +
        "      \"averageDatabaseQueryTime\":0.033605021659486665,\n" +
        "      \"databaseFailedQueryCount\":17549,\n" +
        "      \"averageDatabaseFailedQueryTime\":0.05704028719585168\n" +
        "   }\n" +
        "}";
}
