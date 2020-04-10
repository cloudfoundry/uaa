package org.cloudfoundry.identity.uaa.zone;


public interface IdentityZoneValidator {
    IdentityZone validate(IdentityZone identityZone, Mode mode) throws InvalidIdentityZoneDetailsException;

    enum Mode {
        CREATE, MODIFY, DELETE
    }
}
