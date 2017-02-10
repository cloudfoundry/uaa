/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider;


import java.util.Date;
import org.cloudfoundry.identity.uaa.authentication.GenericPasswordPolicy;

public class PasswordPolicy extends GenericPasswordPolicy<PasswordPolicy> {

    public static final String PASSWORD_POLICY_FIELD = "passwordPolicy";

    private Date passwordNewerThan;

    public PasswordPolicy() {
        super();
    }

    public PasswordPolicy(int minLength,
                          int maxLength,
                          int requireUpperCaseCharacter,
                          int requireLowerCaseCharacter,
                          int requireDigit,
                          int requireSpecialCharacter,
                          int expirePasswordInMonths) {

        super(minLength,
                maxLength,
                requireUpperCaseCharacter,
                requireLowerCaseCharacter,
                requireDigit,
                requireSpecialCharacter,
                expirePasswordInMonths);
    }

    public Date getPasswordNewerThan() {
        return passwordNewerThan;
    }

    public void setPasswordNewerThan(Date passwordNewerThan) {
        this.passwordNewerThan = passwordNewerThan;
    }
}
