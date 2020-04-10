package org.cloudfoundry.identity.uaa.resources;

import java.io.Serializable;

/**
 * Simple wrapper class for vanilla informational responses from REST endpoints.
 *
 * @author Dave Syer
 */
public class ActionResult implements Serializable {

  private String status;

  private String message;

  @SuppressWarnings("unused")
  private ActionResult() {
  }

  public ActionResult(String status, String message) {
    this.status = status;
    this.message = message;
  }

  public String getStatus() {
    return status;
  }

  public String getMessage() {
    return message;
  }

  @Override
  public String toString() {
    return "{\"status\"=\"" + status + "\",\"message\"=\"" + message + "\"}";
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return obj instanceof ActionResult && toString().equals(obj.toString());
  }
}
