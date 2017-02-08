package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.authentication.GenericPasswordPolicy;

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
public class ClientSecretPolicy extends GenericPasswordPolicy<ClientSecretPolicy> {
    public static final String CLIENT_SECRET_POLICY_FIELD = "clientSecretPolicy";

    private int expireSecretInMonths;

    public ClientSecretPolicy() {
        super();
        setExpireSecretInMonths(-1);
    }

    public ClientSecretPolicy(int minLength,
                          int maxLength,
                          int requireUpperCaseCharacter,
                          int requireLowerCaseCharacter,
                          int requireDigit,
                          int requireSpecialCharacter,
                          int expireSecretInMonths) {
        super(minLength,
                maxLength,
                requireUpperCaseCharacter,
                requireLowerCaseCharacter,
                requireDigit,
                requireSpecialCharacter);
        this.setExpireSecretInMonths(expireSecretInMonths);
    }

    public int getExpireSecretInMonths() {
        return expireSecretInMonths;
    }

    public ClientSecretPolicy setExpireSecretInMonths(int expireSecretInMonths) {
        this.expireSecretInMonths = expireSecretInMonths;
        return this;
    }

    @Override
    public boolean allPresentAndPositive() {
        return super.allPresentAndPositive() && expireSecretInMonths >= 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        ClientSecretPolicy that = (ClientSecretPolicy) o;

        return expireSecretInMonths == that.expireSecretInMonths;

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + expireSecretInMonths;
        return result;
    }
}
