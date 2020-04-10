package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URL;

public class VerificationResponse {

  @JsonProperty(value = "verify_link")
  private URL verifyLink;

  public URL getVerifyLink() {
    return verifyLink;
  }

  public void setVerifyLink(URL verifyLink) {
    this.verifyLink = verifyLink;
  }
}
