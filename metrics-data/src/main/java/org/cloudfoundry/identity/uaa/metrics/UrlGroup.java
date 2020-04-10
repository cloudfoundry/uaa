package org.cloudfoundry.identity.uaa.metrics;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.HashMap;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UrlGroup {
  private String pattern;
  private String group;
  private long limit;
  private String category;

  public String getPattern() {
    return pattern;
  }

  public UrlGroup setPattern(String pattern) {
    this.pattern = pattern;
    return this;
  }

  public String getGroup() {
    return group;
  }

  public UrlGroup setGroup(String group) {
    this.group = group;
    return this;
  }

  public long getLimit() {
    return limit;
  }

  public UrlGroup setLimit(long limit) {
    this.limit = limit;
    return this;
  }

  public String getCategory() {
    return category;
  }

  public UrlGroup setCategory(String category) {
    this.category = category;
    return this;
  }

  @JsonIgnore
  public Map<String, Object> getMap() {
    HashMap<String, Object> map = new HashMap<>();
    map.put("pattern", getPattern());
    map.put("group", getGroup());
    map.put("limit", getLimit());
    map.put("category", getCategory());
    return map;
  }

  public static UrlGroup from(Map<String, Object> map) {
    return new UrlGroup()
        .setPattern((String) map.get("pattern"))
        .setGroup((String) map.get("group"))
        .setCategory((String) map.get("category"))
        .setLimit(((Number) map.get("limit")).longValue());
  }
}
