package org.cloudfoundry.identity.uaa.scim;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.util.Date;
import org.cloudfoundry.identity.uaa.impl.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.impl.JsonDateSerializer;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimMeta {

  private int version = 0;

  private Date created = new Date();

  private Date lastModified = null;

  private String[] attributes;

  public ScimMeta() {
  }

  public ScimMeta(Date created, Date lastModified, int version) {
    this.created = created;
    this.lastModified = lastModified;
    this.version = version;
  }

  @JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
  public Date getCreated() {
    return created;
  }

  @JsonDeserialize(using = JsonDateDeserializer.class)
  public void setCreated(Date created) {
    this.created = created;
  }

  @JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
  public Date getLastModified() {
    return lastModified;
  }

  @JsonDeserialize(using = JsonDateDeserializer.class)
  public void setLastModified(Date lastModified) {
    this.lastModified = lastModified;
  }

  public int getVersion() {
    return version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public String[] getAttributes() {
    return attributes;
  }

  public void setAttributes(String[] attributes) {
    this.attributes = attributes;
  }
}
