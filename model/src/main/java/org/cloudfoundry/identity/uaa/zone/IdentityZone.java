package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Calendar;
import java.util.Date;
import javax.validation.constraints.NotNull;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class IdentityZone {

  private String id;
  @NotNull
  private String subdomain;
  private IdentityZoneConfiguration config = new IdentityZoneConfiguration();
  @NotNull
  private String name;
  private int version = 0;
  private String description;
  private Date created = new Date();
  @JsonProperty("last_modified")
  private Date lastModified = new Date();
  private boolean active = true;

  public static IdentityZone getUaa() {
    Calendar calendar = Calendar.getInstance();
    calendar.clear();
    calendar.set(Calendar.YEAR, 2000);
    IdentityZone uaa = new IdentityZone();
    uaa.setCreated(calendar.getTime());
    uaa.setLastModified(calendar.getTime());
    uaa.setVersion(0);
    uaa.setId(OriginKeys.UAA);
    uaa.setName(OriginKeys.UAA);
    uaa.setDescription("The system zone for backwards compatibility");
    uaa.setSubdomain("");
    return uaa;
  }

  public static String getUaaZoneId() {
    return getUaa().getId();
  }

  @JsonIgnore
  public boolean isUaa() {
    return this.equals(getUaa());
  }

  public Date getCreated() {
    return created;
  }

  public void setCreated(Date created) {
    this.created = created;
  }

  public Date getLastModified() {
    return lastModified;
  }

  public void setLastModified(Date lastModified) {
    this.lastModified = lastModified;
  }

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getSubdomain() {
    return subdomain;
  }

  public void setSubdomain(String subdomain) {
    this.subdomain = subdomain;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public IdentityZoneConfiguration getConfig() {
    return config;
  }

  public void setConfig(IdentityZoneConfiguration config) {
    this.config = config;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((id == null) ? 0 : id.hashCode());
    return result;
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
    IdentityZone other = (IdentityZone) obj;
    if (id == null) {
      return other.id == null;
    } else {
      return id.equals(other.id);
    }
  }
}
