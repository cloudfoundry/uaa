package org.cloudfoundry.identity.uaa.scim.exception;

import java.util.Map;
import org.springframework.http.HttpStatus;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class ScimException extends RuntimeException {

  private final HttpStatus status;
  protected Map<String, Object> extraInfo;

  public ScimException(String message, Throwable cause, HttpStatus status) {
    super(message, cause);
    this.status = status;
  }

  public ScimException(String message, HttpStatus status) {
    super(message);
    this.status = status;
  }

  public ScimException(String message, HttpStatus status, Map<String, Object> extraInformation) {
    super(message);
    this.status = status;
    this.extraInfo = extraInformation;
  }

  public HttpStatus getStatus() {
    return status;
  }

  public Map<String, Object> getExtraInfo() {
    return extraInfo;
  }
}
