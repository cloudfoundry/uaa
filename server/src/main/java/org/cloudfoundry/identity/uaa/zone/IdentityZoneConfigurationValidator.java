
package org.cloudfoundry.identity.uaa.zone;


public interface IdentityZoneConfigurationValidator {
    IdentityZoneConfiguration validate(IdentityZone zone, IdentityZoneValidator.Mode mode) throws InvalidIdentityZoneConfigurationException;
}
