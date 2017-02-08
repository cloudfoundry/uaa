package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;

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
public abstract class GenericPasswordPolicy <T extends GenericPasswordPolicy<T>> {

    private int minLength;
    private int maxLength;
    private int requireUpperCaseCharacter;
    private int requireLowerCaseCharacter;
    private int requireDigit;
    private int requireSpecialCharacter;

    public GenericPasswordPolicy() {
        minLength = maxLength = requireUpperCaseCharacter = requireLowerCaseCharacter = requireDigit = requireSpecialCharacter = -1;
    }

    public GenericPasswordPolicy(int minLength,
                          int maxLength,
                          int requireUpperCaseCharacter,
                          int requireLowerCaseCharacter,
                          int requireDigit,
                          int requireSpecialCharacter) {
        this.minLength = minLength;
        this.maxLength = maxLength;
        this.requireUpperCaseCharacter = requireUpperCaseCharacter;
        this.requireLowerCaseCharacter = requireLowerCaseCharacter;
        this.requireDigit = requireDigit;
        this.requireSpecialCharacter = requireSpecialCharacter;
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

    public T setMaxLength(int maxLength) {
        this.maxLength = maxLength;
        return (T)this;
    }

    public T setMinLength(int minLength) {
        this.minLength = minLength;
        return (T)this;
    }

    public T setRequireDigit(int requireDigit) {
        this.requireDigit = requireDigit;
        return (T)this;
    }

    public T setRequireLowerCaseCharacter(int requireLowerCaseCharacter) {
        this.requireLowerCaseCharacter = requireLowerCaseCharacter;
        return (T)this;
    }

    public T setRequireUpperCaseCharacter(int requireUpperCaseCharacter) {
        this.requireUpperCaseCharacter = requireUpperCaseCharacter;
        return (T)this;
    }

    public int getRequireSpecialCharacter() {
        return requireSpecialCharacter;
    }

    public T setRequireSpecialCharacter(int requireSpecialCharacter) {
        this.requireSpecialCharacter = requireSpecialCharacter;
        return (T)this;
    }

    public boolean allPresentAndPositive() {
        return minLength >= 0 && maxLength >= 0 && requireUpperCaseCharacter >= 0 && requireLowerCaseCharacter >= 0 && requireDigit >= 0 && requireSpecialCharacter >= 0;
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
        return true;
    }

    @Override
    public int hashCode() {
        int result = getMinLength();
        result = 31 * result + getMaxLength();
        result = 31 * result + getRequireUpperCaseCharacter();
        result = 31 * result + getRequireLowerCaseCharacter();
        result = 31 * result + getRequireDigit();
        result = 31 * result + getRequireSpecialCharacter();
        return result;
    }
}