package org.cloudfoundry.identity.uaa.metrics;

import java.util.Map;

public interface UaaMetrics {

  long getInflightCount();

  long getIdleTime();

  long getUpTime();

  Map<String, String> getSummary();

  String getGlobals();
}
