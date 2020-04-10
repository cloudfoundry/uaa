package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class ZoneDoesNotExistsException extends UaaException {

  public ZoneDoesNotExistsException(String msg) {
    super("zone_not_found", msg, 404);
  }

  public ZoneDoesNotExistsException(String msg, Throwable cause) {
    super(cause, "zone_not_found", msg, 404);
  }
}
