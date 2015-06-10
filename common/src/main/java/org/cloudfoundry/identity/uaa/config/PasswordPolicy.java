package org.cloudfoundry.identity.uaa.config;

/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
public class PasswordPolicy {

    public static final String PASSWORD_POLICY_FIELD = "passwordPolicy";

    private String specialCharacters;
    private int minLength;
    private int maxLength;
    private int requireUpperCaseCharacter;
    private int requireLowerCaseCharacter;
    private int requireDigit;
    private int requireSpecialCharacter;
    private int expirePasswordInMonths;

    public PasswordPolicy() {
    }

    public PasswordPolicy(int minLength,
                          int maxLength,
                          int requireUpperCaseCharacter,
                          int requireLowerCaseCharacter,
                          int requireDigit,
                          int requireSpecialCharacter,
                          String specialCharacterRegex,
                          int expirePasswordsInMonths) {
        this.minLength = minLength;
        this.maxLength = maxLength;
        this.requireUpperCaseCharacter = requireUpperCaseCharacter;
        this.requireLowerCaseCharacter = requireLowerCaseCharacter;
        this.requireDigit = requireDigit;
        this.requireSpecialCharacter = requireSpecialCharacter;
        this.specialCharacters = specialCharacterRegex;
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

    public void setMaxLength(int maxLength) {
        this.maxLength = maxLength;
    }

    public void setMinLength(int minLength) {
        this.minLength = minLength;
    }

    public void setRequireDigit(int requireDigit) {
        this.requireDigit = requireDigit;
    }

    public void setRequireLowerCaseCharacter(int requireLowerCaseCharacter) {
        this.requireLowerCaseCharacter = requireLowerCaseCharacter;
    }

    public void setRequireUpperCaseCharacter(int requireUpperCaseCharacter) {
        this.requireUpperCaseCharacter = requireUpperCaseCharacter;
    }

    public int getRequireSpecialCharacter() {
        return requireSpecialCharacter;
    }

    public void setRequireSpecialCharacter(int requireSpecialCharacter) {
        this.requireSpecialCharacter = requireSpecialCharacter;
    }

    public String getSpecialCharacters() {
        return specialCharacters;
    }

    public void setSpecialCharacters(String specialCharacters) {
        this.specialCharacters = specialCharacters;
    }

    public int getExpirePasswordInMonths() {
        return expirePasswordInMonths;
    }

    public void setExpirePasswordInMonths(int expirePasswordInMonths) {
        this.expirePasswordInMonths = expirePasswordInMonths;
    }
}
