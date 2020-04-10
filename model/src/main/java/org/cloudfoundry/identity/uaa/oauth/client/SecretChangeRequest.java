package org.cloudfoundry.identity.uaa.oauth.client;

import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.UPDATE;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * SecretChangeRequest.
 *
 * @author Dave Syer
 * @author Luke Taylor
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretChangeRequest {

  private String oldSecret;
  private String secret;
  private String clientId;
  private ChangeMode changeMode = UPDATE;

  public SecretChangeRequest() {
  }

  public SecretChangeRequest(String clientId, String oldSecret, String secret) {
    this.oldSecret = oldSecret;
    this.secret = secret;
    this.clientId = clientId;
  }

  public String getSecret() {
    return secret;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public String getOldSecret() {
    return oldSecret;
  }

  public void setOldSecret(String old) {
    this.oldSecret = old;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public ChangeMode getChangeMode() {
    return changeMode;
  }

  public void setChangeMode(ChangeMode changeMode) {
    this.changeMode = changeMode;
  }

  public enum ChangeMode {
    UPDATE,
    ADD,
    DELETE
  }
}
