package org.cloudfoundry.identity.uaa.metrics;

class MetricsAccessor {

  private static ThreadLocal<RequestMetric> current = ThreadLocal.withInitial(() -> null);

  protected static RequestMetric getCurrent() {
    return current.get();
  }

  protected static void setCurrent(RequestMetric metric) {
    current.set(metric);
  }

  protected static void clear() {
    current.remove();
  }
}
