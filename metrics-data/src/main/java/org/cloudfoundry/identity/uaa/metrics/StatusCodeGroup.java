package org.cloudfoundry.identity.uaa.metrics;

public enum StatusCodeGroup {
  INFORMATIONAL("1xx", 1),
  SUCCESS("2xx", 2),
  REDIRECT("3xx", 3),
  CLIENT_ERROR("4xx", 4),
  SERVER_ERROR("5xx", 5);

  private final String name;
  private final int value;

  StatusCodeGroup(String name, int value) {
    this.name = name;
    this.value = value;
  }

  public String getName() {
    return name;
  }

  public static StatusCodeGroup valueOf(int statusCode) {
    int seriesCode = statusCode / 100;
    for (StatusCodeGroup series : values()) {
      if (series.value == seriesCode) {
        return series;
      }
    }
    throw new IllegalArgumentException("No matching constant for [" + statusCode + "]");
  }
}
