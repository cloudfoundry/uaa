package org.cloudfoundry.identity.uaa.metrics;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.LinkedList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RequestMetric {
  private String uri;
  private UrlGroup uriGroup;
  private int statusCode;
  private long requestStartTime;
  private long requestCompleteTime;
  private List<QueryMetric> queries = new LinkedList<>();

  public static RequestMetric start(String uri, UrlGroup group, long start) {
    RequestMetric metric = new RequestMetric();
    metric.requestStartTime = start;
    metric.uri = uri;
    metric.uriGroup = group;
    return metric;
  }

  public void stop(int statusCode, long stop) {
    this.requestCompleteTime = stop;
    this.statusCode = statusCode;
  }

  public void addQuery(QueryMetric query) {
    queries.add(query);
  }

  @JsonIgnore
  protected List<QueryMetric> getQueries() {
    return queries;
  }

  public String getUri() {
    return uri;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public long getRequestStartTime() {
    return requestStartTime;
  }

  public long getRequestCompleteTime() {
    return requestCompleteTime;
  }

  public long getNrOfDatabaseQueries() {
    return queries.size();
  }

  public long getDatabaseQueryTime() {
    return queries.stream()
        .mapToLong(q -> q.getRequestCompleteTime() - q.getRequestStartTime())
        .sum();
  }

  public UrlGroup getUriGroup() {
    return uriGroup;
  }
}
