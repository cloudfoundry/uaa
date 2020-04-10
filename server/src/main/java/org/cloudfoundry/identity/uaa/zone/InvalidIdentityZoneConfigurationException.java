package org.cloudfoundry.identity.uaa.zone;

public class InvalidIdentityZoneConfigurationException extends Exception {

  public InvalidIdentityZoneConfigurationException(String message, Throwable cause) {
    super(message, cause);
  }

  public InvalidIdentityZoneConfigurationException(String message) {
    super(message);
  }
}
