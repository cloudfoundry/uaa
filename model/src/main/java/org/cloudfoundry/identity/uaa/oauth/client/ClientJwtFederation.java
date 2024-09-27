package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientJwtFederation {

  @JsonProperty("sub")
  private String subject;
  @JsonProperty("iss")
  private String issuer;

  public String getSubject() {
    return this.subject;
  }

  public void setSubject(final String subject) {
    this.subject = subject;
  }

  public String getIssuer() {
    return this.issuer;
  }

  public void setIssuer(final String issuer) {
    this.issuer = issuer;
  }
}
