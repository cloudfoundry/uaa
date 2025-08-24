package org.cloudfoundry.identity.uaa.metrics;

import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.export.notification.NotificationPublisher;
import org.springframework.jmx.export.notification.NotificationPublisherAware;

import java.util.Map;

@ManagedResource(
        objectName = "cloudfoundry.identity:name=ServerRequests",
        description = "UAA Performance Metrics"
)
public class UaaMetricsManagedBean implements UaaMetrics, NotificationPublisherAware {

    private final UaaMetricsFilter filter;


    public UaaMetricsManagedBean(UaaMetricsFilter filter) {
        this.filter = filter;
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Inflight Requests")
    public long getInflightCount() {
        return filter.getInflightCount();
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Idle time (ms)")
    public long getIdleTime() {
        return filter.getIdleTime();
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Total server run time (ms)")
    public long getUpTime() {
        return filter.getUpTime();
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Server Requests for all URI Groups")
    public Map<String, String> getSummary() {
        return filter.getSummary();
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Global Server Request Summary")
    public String getGlobals() {
        return filter.getGlobals();
    }

    @Override
    public void setNotificationPublisher(NotificationPublisher notificationPublisher) {
        filter.setNotificationPublisher(notificationPublisher);
    }

    public boolean isPerRequestMetrics() {
        return filter.isPerRequestMetrics();
    }

    public void setPerRequestMetrics(boolean perRequestMetrics) {
        filter.setPerRequestMetrics(perRequestMetrics);
    }
}
