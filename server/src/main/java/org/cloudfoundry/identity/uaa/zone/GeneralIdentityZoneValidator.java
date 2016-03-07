package org.cloudfoundry.identity.uaa.zone;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class GeneralIdentityZoneValidator implements IdentityZoneValidator {
    private final IdentityZoneConfigurationValidator configValidator;

    public GeneralIdentityZoneValidator() {
        this(new GeneralIdentityZoneConfigurationValidator());
    }

    public GeneralIdentityZoneValidator(IdentityZoneConfigurationValidator configValidator) {
        this.configValidator = configValidator;
    }

    @Override
    public IdentityZone validate(IdentityZone identityZone, Mode mode) throws InvalidIdentityZoneDetailsException {
        try {
            IdentityZoneConfigurationValidator.Mode configValidateMode = null;
            if (mode == Mode.CREATE) {
                configValidateMode = IdentityZoneConfigurationValidator.Mode.CREATE;
            } else if (mode == Mode.MODIFY) {
                configValidateMode = IdentityZoneConfigurationValidator.Mode.MODIFY;
            } else if (mode == Mode.DELETE) {
                configValidateMode = IdentityZoneConfigurationValidator.Mode.DELETE;
            }
            identityZone.setConfig(configValidator.validate(identityZone.getConfig(), configValidateMode));
        } catch (InvalidIdentityZoneConfigurationException ex) {
            throw new InvalidIdentityZoneDetailsException("The zone configuration is invalid.", ex);
        }
        return identityZone;
    }
}
