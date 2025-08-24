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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalMatchers.and;
import static org.mockito.AdditionalMatchers.geq;
import static org.mockito.AdditionalMatchers.gt;
import static org.mockito.AdditionalMatchers.leq;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

class UaaMetricsEmitterTest {

    private MBeanServerConnection server;
    private StatsDClient statsDClient;
    private UaaMetricsEmitter uaaMetricsEmitter;
    private MBeanMap mBeanMap1;
    private MBeanMap mBeanMap2;
    private MetricsUtils metricsUtils;
    private UaaMetrics uaaMetrics1;
    private UaaMetrics uaaMetrics2;
    private NotificationBroadcasterSupport emitter;

    @BeforeEach
    void setUp() throws Exception {
        //mocked in each method
        metricsUtils = mock(MetricsUtils.class);

        Map<String, String> urlGroupJsonMap = new HashMap<>();
        urlGroupJsonMap.put("/ui", UI_JSON);
        urlGroupJsonMap.put("/static-content", STATIC_CONTENT_JSON);

        uaaMetrics1 = mock(UaaMetrics.class);
        when(uaaMetrics1.getGlobals()).thenReturn(GLOBALS_JSON_1);
        when(uaaMetrics1.getSummary()).thenReturn(urlGroupJsonMap);
        when(uaaMetrics1.getIdleTime()).thenReturn(12349L);
        when(uaaMetrics1.getUpTime()).thenReturn(12349843L);
        when(uaaMetrics1.getInflightCount()).thenReturn(3L);

        uaaMetrics2 = mock(UaaMetrics.class);
        when(uaaMetrics2.getGlobals()).thenReturn(GLOBALS_JSON_2);
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
        assertThat(uaaMetricsEmitter.getMetricDelta(name, 5L)).isEqualTo(5L);
        assertThat(uaaMetricsEmitter.getMetricDelta(name, 5L)).isZero();
        assertThat(uaaMetricsEmitter.getMetricDelta(name, 8L)).isEqualTo(3L);
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

    private static final String STATIC_CONTENT_JSON = """
            {
               "lastRequests":[
                  {
                     "uri":"/uaa/resources/oss/stylesheets/application.css",
                     "uriGroup":{
                        "pattern":"/resources/**",
                        "group":"/static-content",
                        "limit":1000,
                        "category":"static-content"
                     },
                     "statusCode":200,
                     "requestStartTime":1508872502264,
                     "requestCompleteTime":1508872502317,
                     "nrOfDatabaseQueries":1,
                     "databaseQueryTime":0
                  },
                  {
                     "uri":"/uaa/resources/oss/images/product-logo.png",
                     "uriGroup":{
                        "pattern":"/resources/**",
                        "group":"/static-content",
                        "limit":1000,
                        "category":"static-content"
                     },
                     "statusCode":200,
                     "requestStartTime":1508872502420,
                     "requestCompleteTime":1508872502434,
                     "nrOfDatabaseQueries":1,
                     "databaseQueryTime":0
                  },
                  {
                     "uri":"/uaa/resources/font/sourcesanspro_regular.woff2",
                     "uriGroup":{
                        "pattern":"/resources/**",
                        "group":"/static-content",
                        "limit":1000,
                        "category":"static-content"
                     },
                     "statusCode":200,
                     "requestStartTime":1508872502497,
                     "requestCompleteTime":1508872502509,
                     "nrOfDatabaseQueries":1,
                     "databaseQueryTime":0
                  },
                  {
                     "uri":"/uaa/resources/font/sourcesanspro_light.woff2",
                     "uriGroup":{
                        "pattern":"/resources/**",
                        "group":"/static-content",
                        "limit":1000,
                        "category":"static-content"
                     },
                     "statusCode":200,
                     "requestStartTime":1508872502498,
                     "requestCompleteTime":1508872502509,
                     "nrOfDatabaseQueries":1,
                     "databaseQueryTime":0
                  },
                  {
                     "uri":"/uaa/resources/oss/images/square-logo.png",
                     "uriGroup":{
                        "pattern":"/resources/**",
                        "group":"/static-content",
                        "limit":1000,
                        "category":"static-content"
                     },
                     "statusCode":200,
                     "requestStartTime":1508872502640,
                     "requestCompleteTime":1508872502647,
                     "nrOfDatabaseQueries":1,
                     "databaseQueryTime":1
                  }
               ],
               "detailed":{
                  "SUCCESS":{
                     "count":6,
                     "averageTime":23.0,
                     "intolerableCount":0,
                     "averageIntolerableTime":0.0,
                     "databaseQueryCount":6,
                     "averageDatabaseQueryTime":0.33333333333333337,
                     "databaseIntolerableQueryCount":0,
                     "averageDatabaseIntolerableQueryTime":0.0
                  }
               },
               "summary":{
                  "count":6,
                  "averageTime":23.0,
                  "intolerableCount":0,
                  "averageIntolerableTime":0.0,
                  "databaseQueryCount":6,
                  "averageDatabaseQueryTime":0.33333333333333337,
                  "databaseIntolerableQueryCount":0,
                  "averageDatabaseIntolerableQueryTime":0.0
               }
            }\
            """;

    private static final String UI_JSON = """
            { \s
               "lastRequests":[  ],
               "detailed":{ \s
                  "REDIRECT":{ \s
                     "count":2,
                     "averageTime":23.0,
                     "intolerableCount":0,
                     "averageIntolerableTime":0.0,
                     "databaseQueryCount":2,
                     "averageDatabaseQueryTime":0.5,
                     "databaseIntolerableQueryCount":0,
                     "averageDatabaseIntolerableQueryTime":0.0
                  },
                  "SUCCESS":{ \s
                     "count":2,
                     "averageTime":578.0,
                     "intolerableCount":0,
                     "averageIntolerableTime":0.0,
                     "databaseQueryCount":24,
                     "averageDatabaseQueryTime":0.08333333333333333,
                     "databaseIntolerableQueryCount":0,
                     "averageDatabaseIntolerableQueryTime":0.0
                  }
               },
               "summary":{ \s
                  "count":4,
                  "averageTime":300.5,
                  "intolerableCount":0,
                  "averageIntolerableTime":0.0,
                  "databaseQueryCount":26,
                  "averageDatabaseQueryTime":0.11538461538461539,
                  "databaseIntolerableQueryCount":0,
                  "averageDatabaseIntolerableQueryTime":0.0
               }
            }\
            """;

    private static final String GLOBALS_JSON_1 = """
            {
               "lastRequests":[
                  {
                     "uri":"/uaa/",
                     "statusCode":302,
                     "requestStartTime":1506021406240,
                     "requestCompleteTime":1506021406260,
                     "nrOfDatabaseQueries":1,
                     "databaseQueryTime":0
                  },
                  {
                     "uri":"/uaa/login",
                     "statusCode":200,
                     "requestStartTime":1506021406265,
                     "requestCompleteTime":1506021406970,
                     "nrOfDatabaseQueries":12,
                     "databaseQueryTime":0
                  },
                  {
                     "uri":"/uaa/",
                     "statusCode":302,
                     "requestStartTime":1506021407210,
                     "requestCompleteTime":1506021407216,
                     "nrOfDatabaseQueries":1,
                     "databaseQueryTime":1
                  },
                  {
                     "uri":"/uaa/login",
                     "statusCode":200,
                     "requestStartTime":1506021407224,
                     "requestCompleteTime":1506021407284,
                     "nrOfDatabaseQueries":12,
                     "databaseQueryTime":0
                  },
                  {
                     "uri":"/uaa/resources/oss/stylesheets/application.css",
                     "statusCode":304,
                     "requestStartTime":1506021407293,
                     "requestCompleteTime":1506021407331,
                     "nrOfDatabaseQueries":1,
                     "databaseQueryTime":0
                  }
               ],
               "detailed":{
                  "SERVER_ERROR":{
                     "count":1,
                     "averageTime":87.0,
                     "intolerableCount":0,
                     "averageIntolerableTime":0.0,
                     "databaseQueryCount":13,
                     "averageDatabaseQueryTime":0.0,
                     "databaseIntolerableQueryCount":0,
                     "averageDatabaseIntolerableQueryTime":0.0
                  },
                  "REDIRECT":{
                     "count":763,
                     "averageTime":35.86107470511138,
                     "intolerableCount":1,
                     "averageIntolerableTime":4318.0,
                     "databaseQueryCount":5428,
                     "averageDatabaseQueryTime":0.028002947678703018,
                     "databaseIntolerableQueryCount":188,
                     "averageDatabaseIntolerableQueryTime":0.047872340425531915
                  },
                  "SUCCESS":{
                     "count":2148,
                     "averageTime":28.867318435754207,
                     "intolerableCount":0,
                     "averageIntolerableTime":0.0,
                     "databaseQueryCount":77513,
                     "averageDatabaseQueryTime":0.0341362094100345,
                     "databaseIntolerableQueryCount":17327,
                     "averageDatabaseIntolerableQueryTime":0.057136261326253886
                  },
                  "CLIENT_ERROR":{
                     "count":175,
                     "averageTime":15.097142857142877,
                     "intolerableCount":0,
                     "averageIntolerableTime":0.0,
                     "databaseQueryCount":843,
                     "averageDatabaseQueryTime":0.021352313167259794,
                     "databaseIntolerableQueryCount":34,
                     "averageDatabaseIntolerableQueryTime":0.058823529411764705
                  }
               },
               "summary":{
                  "count":3087,
                  "averageTime":29.834143181081966,
                  "intolerableCount":1,
                  "averageIntolerableTime":4318.0,
                  "databaseQueryCount":83797,
                  "averageDatabaseQueryTime":0.033605021659486665,
                  "databaseIntolerableQueryCount":17549,
                  "averageDatabaseIntolerableQueryTime":0.05704028719585168
               }
            }\
            """;

    //values have increased
    private static final String GLOBALS_JSON_2 = GLOBALS_JSON_1
            .replace("\"count\":3087,\n", "\"count\":3091,\n") //total
            .replace("         \"count\":763,\n", "         \"count\":764,\n") //redirect
            .replace("         \"count\":175,\n", "         \"count\":176,\n") //client_error
            .replace("         \"count\":2148,\n", "         \"count\":2149,\n") //success
            .replace("         \"count\":1,\n", "         \"count\":2,\n") //error
            .replace("         \"databaseQueryCount\":77513,\n", "         \"databaseQueryCount\":77515,\n") //database count
            .replace("         \"databaseIntolerableQueryCount\":17327,\n", "         \"databaseIntolerableQueryCount\":17332,\n") //database unhealthy count
            .replace("         \"intolerableCount\":1,\n", "         \"intolerableCount\":2,\n"); //intolerable count
}
