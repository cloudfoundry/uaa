package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.util.StringUtils;

public class Prompt {

  private final String name;
  private final String text;
  private final String type;

  @JsonCreator
  public Prompt(
      @JsonProperty("name") String name,
      @JsonProperty("type") String type,
      @JsonProperty("text") String text) {
    this.name = name;
    this.type = type;
    this.text = text;
  }

  public static Prompt valueOf(String text) {
    if (!StringUtils.hasText(text)) {
      return null;
    }
    String[] parts = text.split(":");
    if (parts.length < 2) {
      return null;
    }
    String name = parts[0].replaceAll("\"", "");
    String[] values =
        parts[1].replaceAll("\"", "").replaceAll("\\[", "").replaceAll("\\]", "").split(",");
    values = StringUtils.trimArrayElements(values);
    return new Prompt(name, values[0], values[1]);
  }

  public String getName() {
    return name;
  }

  public String getText() {
    return text;
  }

  public String getType() {
    return type;
  }

  @JsonIgnore
  public String[] getDetails() {
    return new String[] {type, text};
  }

  @Override
  public String toString() {
    return String.format("\"%s\":[\"%s\",\"%s\"]", name, type, text);
  }

  @Override
  public int hashCode() {
    return 31 + toString().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    Prompt other = (Prompt) obj;
    return toString().equals(other.toString());
  }
}
