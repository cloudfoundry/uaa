package org.cloudfoundry.identity.uaa.codestore;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.sql.Timestamp;
import java.util.Objects;

@JsonSerialize
@JsonDeserialize
public class ExpiringCode {

  private String code;

  private Timestamp expiresAt;

  private String data;

  private String intent;

  public ExpiringCode() {
  }

  public ExpiringCode(String code, Timestamp expiresAt, String data, String intent) {
    this.code = code;
    this.expiresAt = expiresAt;
    this.data = data;
    this.intent = intent;
  }

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }

  public Timestamp getExpiresAt() {
    return expiresAt;
  }

  public void setExpiresAt(Timestamp expiresAt) {
    this.expiresAt = expiresAt;
  }

  public String getData() {
    return data;
  }

  public void setData(String data) {
    this.data = data;
  }

  public String getIntent() {
    return intent;
  }

  public void setIntent(String intent) {
    this.intent = intent;
  }

  @JsonIgnore
  public boolean isExpired() {
    if (expiresAt == null) {
      return false;
    }
    return expiresAt.getTime() < System.currentTimeMillis();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof ExpiringCode)) {
      return false;
    }

    ExpiringCode that = (ExpiringCode) o;

    if (!Objects.equals(code, that.code)) {
      return false;
    }
    if (!Objects.equals(data, that.data)) {
      return false;
    }
    if (!Objects.equals(expiresAt, that.expiresAt)) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    return code != null ? code.hashCode() : 0;
  }

  @Override
  public String toString() {
    return "ExpiringCode [code="
        + code
        + ", expiresAt="
        + expiresAt
        + ", data="
        + trimToLength(data, 1024)
        + ", intent="
        + intent
        + "]";
  }

  private String trimToLength(String s, int length) {
    int min = Math.min(s.length(), length);
    if (min == s.length()) {
      return s;
    } else {
      return s.substring(0, min);
    }
  }
}
