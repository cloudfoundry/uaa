package org.cloudfoundry.identity.uaa.zone;



public interface ClientSecretValidator {

    /**
     * Validates the client secret as to whether it conforms to the validation rules.
     *  @param clientSecret the trial clientSecret
     *
     */
    void validate(String clientSecret) throws InvalidClientSecretException;
}
