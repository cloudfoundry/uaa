package org.cloudfoundry.identity.statsd;

import com.timgroup.statsd.ConvenienceMethodProvidingStatsDClient;
import com.timgroup.statsd.StatsDClient;
import org.cloudfoundry.identity.uaa.metrics.UaaMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.management.MBeanServerConnection;
import javax.management.Notification;
import javax.management.NotificationBroadcasterSupport;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.AdditionalMatchers.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class UaaMetricsEmitterTest {

    private MBeanServerConnection server;
    private StatsDClient statsDClient;
    private UaaMetricsEmitter uaaMetricsEmitter;
    private MBeanMap mBeanMap1;
    private MBeanMap mBeanMap2;
    private MetricsUtils metricsUtils;
    private UaaMetrics uaaMetrics1, uaaMetrics2;
    private NotificationBroadcasterSupport emitter;

    @BeforeEach
    void setUp() throws Exception {
        //mocked in each method
        metricsUtils = mock(MetricsUtils.class);

        Map<String, String> urlGroupJsonMap = new HashMap<>();
        urlGroupJsonMap.put("/ui", uiJson);
        urlGroupJsonMap.put("/static-content", staticContentJson);

        uaaMetrics1 = mock(UaaMetrics.class);
        when(uaaMetrics1.getGlobals()).thenReturn(globalsJson1);
        when(uaaMetrics1.getSummary()).thenReturn(urlGroupJsonMap);
        when(uaaMetrics1.getIdleTime()).thenReturn(12349L);
        when(uaaMetrics1.getUpTime()).thenReturn(12349843L);
        when(uaaMetrics1.getInflightCount()).thenReturn(3L);

        uaaMetrics2 = mock(UaaMetrics.class);
        when(uaaMetrics2.getGlobals()).thenReturn(globalsJson2);
        when(uaaMetrics2.getSummary()).thenReturn(urlGroupJsonMap);
        when(uaaMetrics2.getIdleTime()).thenReturn(12349L);
        when(uaaMetrics2.getUpTime()).thenReturn(12349843L);
        when(uaaMetrics2.getInflightCount()).thenReturn(3L);

        server = mock(MBeanServerConnection.class);

        emitter = new NotificationBroadcasterSupport();
        when(metricsUtils.getUaaMetricsSubscriber(any())).thenReturn(emitter);

        statsDClient = mock(ConvenienceMethodProvidingStatsDClient.class);
        uaaMetricsEmitter = new UaaMetricsEmitter(metricsUtils, statsDClient, server);

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
    }

    @Test
    void auditService_metrics_emitted() throws Exception {
        Mockito.when(metricsUtils.pullUpMap("cloudfoundry.identity", "*", server)).thenReturn((Map) mBeanMap2);
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
    void requestCount_metrics_emitted() throws Exception {
        Mockito.when(metricsUtils.getUaaMetrics(any())).thenReturn(uaaMetrics1, uaaMetrics2);
        uaaMetricsEmitter.emitGlobalRequestMetrics();
        Mockito.verify(statsDClient).count("requests.global.completed.count", 3087L);
        Mockito.verify(statsDClient).gauge("requests.global.completed.time", 29L);
        Mockito.verify(statsDClient).count("requests.global.unhealthy.count", 1L);
        Mockito.verify(statsDClient).gauge("requests.global.unhealthy.time", 4318L);
        Mockito.verify(statsDClient).count("requests.global.status_1xx.count", 0L);
        Mockito.verify(statsDClient).count("requests.global.status_2xx.count", 2148L);
        Mockito.verify(statsDClient).count("requests.global.status_3xx.count", 763L);
        Mockito.verify(statsDClient).count("requests.global.status_4xx.count", 175L);
        Mockito.verify(statsDClient).count("requests.global.status_5xx.count", 1L);
        Mockito.verify(statsDClient).gauge("server.inflight.count", 3L);
        Mockito.verify(statsDClient).gauge("server.up.time", 12349843L);
        Mockito.verify(statsDClient).gauge("server.idle.time", 12349L);
        Mockito.verify(statsDClient).count("database.global.completed.count", 83797L);
        Mockito.verify(statsDClient).gauge("database.global.completed.time", 0L);
        Mockito.verify(statsDClient).count("database.global.unhealthy.count", 17549L);
        Mockito.verify(statsDClient).gauge("database.global.unhealthy.time", 0L);
        reset(statsDClient);
        uaaMetricsEmitter.emitGlobalRequestMetrics();
        Mockito.verify(statsDClient).count("requests.global.completed.count", 4L);
        Mockito.verify(statsDClient).count("requests.global.unhealthy.count", 1L);
        Mockito.verify(statsDClient).count("requests.global.status_1xx.count", 0L);
        Mockito.verify(statsDClient).count("requests.global.status_2xx.count", 1L);
        Mockito.verify(statsDClient).count("requests.global.status_3xx.count", 1L);
        Mockito.verify(statsDClient).count("requests.global.status_4xx.count", 1L);
        Mockito.verify(statsDClient).count("requests.global.status_5xx.count", 1L);
        Mockito.verify(statsDClient).count("database.global.completed.count", 2L);
        Mockito.verify(statsDClient).count("database.global.unhealthy.count", 5L);
        reset(statsDClient);
        uaaMetricsEmitter.emitGlobalRequestMetrics();
        Mockito.verify(statsDClient).count("requests.global.completed.count", 0L);
        Mockito.verify(statsDClient).count("requests.global.unhealthy.count", 0L);
        Mockito.verify(statsDClient).count("requests.global.status_1xx.count", 0L);
        Mockito.verify(statsDClient).count("requests.global.status_2xx.count", 0L);
        Mockito.verify(statsDClient).count("requests.global.status_3xx.count", 0L);
        Mockito.verify(statsDClient).count("requests.global.status_4xx.count", 0L);
        Mockito.verify(statsDClient).count("requests.global.status_5xx.count", 0L);
        Mockito.verify(statsDClient).count("database.global.completed.count", 0L);
        Mockito.verify(statsDClient).count("database.global.unhealthy.count", 0L);
    }

    @Test
    void getMetricDelta() {
        String name = "metric.name";
        assertEquals(5L, uaaMetricsEmitter.getMetricDelta(name, 5L));
        assertEquals(0L, uaaMetricsEmitter.getMetricDelta(name, 5L));
        assertEquals(3L, uaaMetricsEmitter.getMetricDelta(name, 8L));
    }

    @Test
    void vm_vitals() {
        uaaMetricsEmitter.emitVmVitals();
        Mockito.verify(statsDClient).gauge(eq("vitals.vm.cpu.count"), gt(0L));
        Mockito.verify(statsDClient).gauge(eq("vitals.vm.cpu.load"), geq(0L));
        Mockito.verify(statsDClient).gauge(eq("vitals.vm.memory.total"), geq(134217728L));
        Mockito.verify(statsDClient).gauge(eq("vitals.vm.memory.committed"), geq(1L));
        Mockito.verify(statsDClient).gauge(eq("vitals.vm.memory.free"), geq(1L));
    }

    @Test
    void perUrlGroup_request_metrics() throws Exception {
        Mockito.when(metricsUtils.getUaaMetrics(any())).thenReturn(uaaMetrics1);
        uaaMetricsEmitter.emitUrlGroupRequestMetrics();
        Mockito.verify(statsDClient).gauge(eq("requests.ui.completed.count"), gt(0L));
        Mockito.verify(statsDClient).gauge(eq("requests.ui.completed.time"), geq(300L));

        Mockito.verify(statsDClient).gauge(eq("requests.static-content.completed.count"), gt(0L));
        Mockito.verify(statsDClient).gauge(eq("requests.static-content.completed.time"), geq(23L));
    }

    @Test
    void sendNotification() {
        uaaMetricsEmitter.enableNotification();
        emitter.sendNotification(new Notification("/api", 45L, 0));
        Mockito.verify(statsDClient).time("requests.api.latency", 45L);
    }

    @Test
    void jvm_vitals() {
        uaaMetricsEmitter.emitJvmVitals();
        Mockito.verify(statsDClient).gauge(eq("vitals.jvm.cpu.load"), and(geq(0L), leq(100L)));
        Mockito.verify(statsDClient).gauge(eq("vitals.jvm.thread.count"), and(gt(1L), leq(1000L)));
        Mockito.verify(statsDClient).gauge(eq("vitals.jvm.heap.init"), gt(0L));
        Mockito.verify(statsDClient).gauge(eq("vitals.jvm.heap.committed"), gt(0L));
        Mockito.verify(statsDClient).gauge(eq("vitals.jvm.heap.used"), gt(0L));
        //Mockito.verify(statsDClient).gauge(eq("vitals.jvm.heap.max"), gt(0l));
        Mockito.verify(statsDClient).gauge(eq("vitals.jvm.non-heap.init"), gt(0L));
        Mockito.verify(statsDClient).gauge(eq("vitals.jvm.non-heap.committed"), gt(0L));
        Mockito.verify(statsDClient).gauge(eq("vitals.jvm.non-heap.used"), gt(0L));
        //Mockito.verify(statsDClient).gauge(eq("vitals.jvm.non-heap.max"), gt(0l));
    }

    @Test
    void auditService_metricValues_areNull() throws Exception {
        mBeanMap1.put("user_authentication_count", null);
        Mockito.when(metricsUtils.pullUpMap("cloudfoundry.identity", "*", server)).thenReturn((Map) mBeanMap2);
        uaaMetricsEmitter.emitMetrics();
        Mockito.verify(statsDClient).gauge("audit_service.user_not_found_count", 1);
        Mockito.verify(statsDClient, times(6)).gauge(anyString(), anyLong());
    }

    @Test
    void auditService_Key_isNull() throws Exception {
        mBeanMap2.put("UaaAudit", null);
        Mockito.when(metricsUtils.pullUpMap("cloudfoundry.identity", "*", server)).thenReturn((Map) mBeanMap2);
        uaaMetricsEmitter.emitMetrics();
        Mockito.verify(statsDClient, times(0)).gauge(anyString(), anyLong());
    }

    private String staticContentJson = "{\n" +
            "   \"lastRequests\":[\n" +
            "      {\n" +
            "         \"uri\":\"/uaa/resources/oss/stylesheets/application.css\",\n" +
            "         \"uriGroup\":{\n" +
            "            \"pattern\":\"/resources/**\",\n" +
            "            \"group\":\"/static-content\",\n" +
            "            \"limit\":1000,\n" +
            "            \"category\":\"static-content\"\n" +
            "         },\n" +
            "         \"statusCode\":200,\n" +
            "         \"requestStartTime\":1508872502264,\n" +
            "         \"requestCompleteTime\":1508872502317,\n" +
            "         \"nrOfDatabaseQueries\":1,\n" +
            "         \"databaseQueryTime\":0\n" +
            "      },\n" +
            "      {\n" +
            "         \"uri\":\"/uaa/resources/oss/images/product-logo.png\",\n" +
            "         \"uriGroup\":{\n" +
            "            \"pattern\":\"/resources/**\",\n" +
            "            \"group\":\"/static-content\",\n" +
            "            \"limit\":1000,\n" +
            "            \"category\":\"static-content\"\n" +
            "         },\n" +
            "         \"statusCode\":200,\n" +
            "         \"requestStartTime\":1508872502420,\n" +
            "         \"requestCompleteTime\":1508872502434,\n" +
            "         \"nrOfDatabaseQueries\":1,\n" +
            "         \"databaseQueryTime\":0\n" +
            "      },\n" +
            "      {\n" +
            "         \"uri\":\"/uaa/resources/font/sourcesanspro_regular.woff2\",\n" +
            "         \"uriGroup\":{\n" +
            "            \"pattern\":\"/resources/**\",\n" +
            "            \"group\":\"/static-content\",\n" +
            "            \"limit\":1000,\n" +
            "            \"category\":\"static-content\"\n" +
            "         },\n" +
            "         \"statusCode\":200,\n" +
            "         \"requestStartTime\":1508872502497,\n" +
            "         \"requestCompleteTime\":1508872502509,\n" +
            "         \"nrOfDatabaseQueries\":1,\n" +
            "         \"databaseQueryTime\":0\n" +
            "      },\n" +
            "      {\n" +
            "         \"uri\":\"/uaa/resources/font/sourcesanspro_light.woff2\",\n" +
            "         \"uriGroup\":{\n" +
            "            \"pattern\":\"/resources/**\",\n" +
            "            \"group\":\"/static-content\",\n" +
            "            \"limit\":1000,\n" +
            "            \"category\":\"static-content\"\n" +
            "         },\n" +
            "         \"statusCode\":200,\n" +
            "         \"requestStartTime\":1508872502498,\n" +
            "         \"requestCompleteTime\":1508872502509,\n" +
            "         \"nrOfDatabaseQueries\":1,\n" +
            "         \"databaseQueryTime\":0\n" +
            "      },\n" +
            "      {\n" +
            "         \"uri\":\"/uaa/resources/oss/images/square-logo.png\",\n" +
            "         \"uriGroup\":{\n" +
            "            \"pattern\":\"/resources/**\",\n" +
            "            \"group\":\"/static-content\",\n" +
            "            \"limit\":1000,\n" +
            "            \"category\":\"static-content\"\n" +
            "         },\n" +
            "         \"statusCode\":200,\n" +
            "         \"requestStartTime\":1508872502640,\n" +
            "         \"requestCompleteTime\":1508872502647,\n" +
            "         \"nrOfDatabaseQueries\":1,\n" +
            "         \"databaseQueryTime\":1\n" +
            "      }\n" +
            "   ],\n" +
            "   \"detailed\":{\n" +
            "      \"SUCCESS\":{\n" +
            "         \"count\":6,\n" +
            "         \"averageTime\":23.0,\n" +
            "         \"intolerableCount\":0,\n" +
            "         \"averageIntolerableTime\":0.0,\n" +
            "         \"databaseQueryCount\":6,\n" +
            "         \"averageDatabaseQueryTime\":0.33333333333333337,\n" +
            "         \"databaseIntolerableQueryCount\":0,\n" +
            "         \"averageDatabaseIntolerableQueryTime\":0.0\n" +
            "      }\n" +
            "   },\n" +
            "   \"summary\":{\n" +
            "      \"count\":6,\n" +
            "      \"averageTime\":23.0,\n" +
            "      \"intolerableCount\":0,\n" +
            "      \"averageIntolerableTime\":0.0,\n" +
            "      \"databaseQueryCount\":6,\n" +
            "      \"averageDatabaseQueryTime\":0.33333333333333337,\n" +
            "      \"databaseIntolerableQueryCount\":0,\n" +
            "      \"averageDatabaseIntolerableQueryTime\":0.0\n" +
            "   }\n" +
            "}";

    private String uiJson = "{  \n" +
            "   \"lastRequests\":[  ],\n" +
            "   \"detailed\":{  \n" +
            "      \"REDIRECT\":{  \n" +
            "         \"count\":2,\n" +
            "         \"averageTime\":23.0,\n" +
            "         \"intolerableCount\":0,\n" +
            "         \"averageIntolerableTime\":0.0,\n" +
            "         \"databaseQueryCount\":2,\n" +
            "         \"averageDatabaseQueryTime\":0.5,\n" +
            "         \"databaseIntolerableQueryCount\":0,\n" +
            "         \"averageDatabaseIntolerableQueryTime\":0.0\n" +
            "      },\n" +
            "      \"SUCCESS\":{  \n" +
            "         \"count\":2,\n" +
            "         \"averageTime\":578.0,\n" +
            "         \"intolerableCount\":0,\n" +
            "         \"averageIntolerableTime\":0.0,\n" +
            "         \"databaseQueryCount\":24,\n" +
            "         \"averageDatabaseQueryTime\":0.08333333333333333,\n" +
            "         \"databaseIntolerableQueryCount\":0,\n" +
            "         \"averageDatabaseIntolerableQueryTime\":0.0\n" +
            "      }\n" +
            "   },\n" +
            "   \"summary\":{  \n" +
            "      \"count\":4,\n" +
            "      \"averageTime\":300.5,\n" +
            "      \"intolerableCount\":0,\n" +
            "      \"averageIntolerableTime\":0.0,\n" +
            "      \"databaseQueryCount\":26,\n" +
            "      \"averageDatabaseQueryTime\":0.11538461538461539,\n" +
            "      \"databaseIntolerableQueryCount\":0,\n" +
            "      \"averageDatabaseIntolerableQueryTime\":0.0\n" +
            "   }\n" +
            "}";

    private String globalsJson1 = "{\n" +
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
            "         \"databaseIntolerableQueryCount\":0,\n" +
            "         \"averageDatabaseIntolerableQueryTime\":0.0\n" +
            "      },\n" +
            "      \"REDIRECT\":{\n" +
            "         \"count\":763,\n" +
            "         \"averageTime\":35.86107470511138,\n" +
            "         \"intolerableCount\":1,\n" +
            "         \"averageIntolerableTime\":4318.0,\n" +
            "         \"databaseQueryCount\":5428,\n" +
            "         \"averageDatabaseQueryTime\":0.028002947678703018,\n" +
            "         \"databaseIntolerableQueryCount\":188,\n" +
            "         \"averageDatabaseIntolerableQueryTime\":0.047872340425531915\n" +
            "      },\n" +
            "      \"SUCCESS\":{\n" +
            "         \"count\":2148,\n" +
            "         \"averageTime\":28.867318435754207,\n" +
            "         \"intolerableCount\":0,\n" +
            "         \"averageIntolerableTime\":0.0,\n" +
            "         \"databaseQueryCount\":77513,\n" +
            "         \"averageDatabaseQueryTime\":0.0341362094100345,\n" +
            "         \"databaseIntolerableQueryCount\":17327,\n" +
            "         \"averageDatabaseIntolerableQueryTime\":0.057136261326253886\n" +
            "      },\n" +
            "      \"CLIENT_ERROR\":{\n" +
            "         \"count\":175,\n" +
            "         \"averageTime\":15.097142857142877,\n" +
            "         \"intolerableCount\":0,\n" +
            "         \"averageIntolerableTime\":0.0,\n" +
            "         \"databaseQueryCount\":843,\n" +
            "         \"averageDatabaseQueryTime\":0.021352313167259794,\n" +
            "         \"databaseIntolerableQueryCount\":34,\n" +
            "         \"averageDatabaseIntolerableQueryTime\":0.058823529411764705\n" +
            "      }\n" +
            "   },\n" +
            "   \"summary\":{\n" +
            "      \"count\":3087,\n" +
            "      \"averageTime\":29.834143181081966,\n" +
            "      \"intolerableCount\":1,\n" +
            "      \"averageIntolerableTime\":4318.0,\n" +
            "      \"databaseQueryCount\":83797,\n" +
            "      \"averageDatabaseQueryTime\":0.033605021659486665,\n" +
            "      \"databaseIntolerableQueryCount\":17549,\n" +
            "      \"averageDatabaseIntolerableQueryTime\":0.05704028719585168\n" +
            "   }\n" +
            "}";

    //values have increased
    private String globalsJson2 = globalsJson1
            .replace("\"count\":3087,\n", "\"count\":3091,\n") //total
            .replace("         \"count\":763,\n", "         \"count\":764,\n") //redirect
            .replace("         \"count\":175,\n", "         \"count\":176,\n") //client_error
            .replace("         \"count\":2148,\n", "         \"count\":2149,\n") //success
            .replace("         \"count\":1,\n", "         \"count\":2,\n") //error
            .replace("         \"databaseQueryCount\":77513,\n", "         \"databaseQueryCount\":77515,\n") //database count
            .replace("         \"databaseIntolerableQueryCount\":17327,\n", "         \"databaseIntolerableQueryCount\":17332,\n") //database unhealthy count
            .replace("         \"intolerableCount\":1,\n", "         \"intolerableCount\":2,\n"); //intolerable count
}
