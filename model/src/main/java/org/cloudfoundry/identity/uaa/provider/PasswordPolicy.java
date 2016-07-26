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


public class PasswordPolicy {

    public static final String PASSWORD_POLICY_FIELD = "passwordPolicy";

    private int minLength;
    private int maxLength;
    private int requireUpperCaseCharacter;
    private int requireLowerCaseCharacter;
    private int requireDigit;
    private int requireSpecialCharacter;
    private int expirePasswordInMonths;

    public PasswordPolicy() {
        minLength = maxLength = requireUpperCaseCharacter = requireLowerCaseCharacter = requireDigit = requireSpecialCharacter = expirePasswordInMonths = -1;
    }

    public PasswordPolicy(int minLength,
                          int maxLength,
                          int requireUpperCaseCharacter,
                          int requireLowerCaseCharacter,
                          int requireDigit,
                          int requireSpecialCharacter,
                          int expirePasswordsInMonths) {
        this.minLength = minLength;
        this.maxLength = maxLength;
        this.requireUpperCaseCharacter = requireUpperCaseCharacter;
        this.requireLowerCaseCharacter = requireLowerCaseCharacter;
        this.requireDigit = requireDigit;
        this.requireSpecialCharacter = requireSpecialCharacter;
        this.expirePasswordInMonths = expirePasswordsInMonths;
    }

    public int getMinLength() {
        return minLength;
    }

    public int getMaxLength() {
        return maxLength;
    }

    public int getRequireUpperCaseCharacter() {
        return requireUpperCaseCharacter;
    }

    public int getRequireLowerCaseCharacter() {
        return requireLowerCaseCharacter;
    }

    public int getRequireDigit() {
        return requireDigit;
    }

    public PasswordPolicy setMaxLength(int maxLength) {
        this.maxLength = maxLength;
        return this;
    }

    public PasswordPolicy setMinLength(int minLength) {
        this.minLength = minLength;
        return this;
    }

    public PasswordPolicy setRequireDigit(int requireDigit) {
        this.requireDigit = requireDigit;
        return this;
    }

    public PasswordPolicy setRequireLowerCaseCharacter(int requireLowerCaseCharacter) {
        this.requireLowerCaseCharacter = requireLowerCaseCharacter;
        return this;
    }

    public PasswordPolicy setRequireUpperCaseCharacter(int requireUpperCaseCharacter) {
        this.requireUpperCaseCharacter = requireUpperCaseCharacter;
        return this;
    }

    public int getRequireSpecialCharacter() {
        return requireSpecialCharacter;
    }

    public PasswordPolicy setRequireSpecialCharacter(int requireSpecialCharacter) {
        this.requireSpecialCharacter = requireSpecialCharacter;
        return this;
    }

    public int getExpirePasswordInMonths() {
        return expirePasswordInMonths;
    }

    public PasswordPolicy setExpirePasswordInMonths(int expirePasswordInMonths) {
        this.expirePasswordInMonths = expirePasswordInMonths;
        return this;
    }

    public boolean allPresentAndPositive() {
        return minLength >= 0 && maxLength >= 0 && requireUpperCaseCharacter >= 0 && requireLowerCaseCharacter >= 0 && requireDigit >= 0 && requireSpecialCharacter >= 0 && expirePasswordInMonths >= 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PasswordPolicy that = (PasswordPolicy) o;

        if (getMinLength() != that.getMinLength()) return false;
        if (getMaxLength() != that.getMaxLength()) return false;
        if (getRequireUpperCaseCharacter() != that.getRequireUpperCaseCharacter()) return false;
        if (getRequireLowerCaseCharacter() != that.getRequireLowerCaseCharacter()) return false;
        if (getRequireDigit() != that.getRequireDigit()) return false;
        if (getRequireSpecialCharacter() != that.getRequireSpecialCharacter()) return false;
        return getExpirePasswordInMonths() == that.getExpirePasswordInMonths();

    }

    @Override
    public int hashCode() {
        int result = getMinLength();
        result = 31 * result + getMaxLength();
        result = 31 * result + getRequireUpperCaseCharacter();
        result = 31 * result + getRequireLowerCaseCharacter();
        result = 31 * result + getRequireDigit();
        result = 31 * result + getRequireSpecialCharacter();
        result = 31 * result + getExpirePasswordInMonths();
        return result;
    }
}
