package org.cloudfoundry.identity.uaa.metrics;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class QueryMetric {
  private String query;
  private boolean intolerable;
  private long requestStartTime;
  private long requestCompleteTime;

  public QueryMetric(String query, long start, long delta, boolean intolerable) {
    this.query = query;
    this.intolerable = intolerable;
    this.requestStartTime = start;
    this.requestCompleteTime = start + delta;
  }

  public String getQuery() {
    return query;
  }

  public boolean isIntolerable() {
    return intolerable;
  }

  public long getRequestStartTime() {
    return requestStartTime;
  }

  public long getRequestCompleteTime() {
    return requestCompleteTime;
  }
}
