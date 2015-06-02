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

    public static String PASSWORD_POLICY_FIELD = "passwordPolicy";

    public static PasswordPolicy getDefault() {
        return new PasswordPolicy(8, 128, true, true, true, false);
    }

    private Integer minLength;
    private Integer maxLength;
    private boolean requireAtLeastOneUpperCaseCharacter;
    private boolean requireAtLeastOneLowerCaseCharacter;
    private boolean requireAtLeastOneDigit;
    private boolean requireAtLeastOneSpecialCharacter;

    public PasswordPolicy() {
    }

    public PasswordPolicy(Integer minLength, Integer maxLength,
                          boolean requireAtLeastOneUpperCaseCharacter,
                          boolean requireAtLeastOneLowerCaseCharacter,
                          boolean requireAtLeastOneDigit,
                          boolean requireAtLeastOneSpecialCharacter) {
        this.minLength = minLength;
        this.maxLength = maxLength;
        this.requireAtLeastOneUpperCaseCharacter = requireAtLeastOneUpperCaseCharacter;
        this.requireAtLeastOneLowerCaseCharacter = requireAtLeastOneLowerCaseCharacter;
        this.requireAtLeastOneDigit = requireAtLeastOneDigit;
        this.requireAtLeastOneSpecialCharacter = requireAtLeastOneSpecialCharacter;
    }

    public Integer getMinLength() {
        return minLength;
    }

    public Integer getMaxLength() {
        return maxLength;
    }

    public boolean isRequireAtLeastOneUpperCaseCharacter() {
        return requireAtLeastOneUpperCaseCharacter;
    }

    public boolean isRequireAtLeastOneLowerCaseCharacter() {
        return requireAtLeastOneLowerCaseCharacter;
    }

    public boolean isRequireAtLeastOneDigit() {
        return requireAtLeastOneDigit;
    }

    public boolean isRequireAtLeastOneSpecialCharacter() {
        return requireAtLeastOneSpecialCharacter;
    }

    public void setRequireAtLeastOneSpecialCharacter(boolean requireAtLeastOneSpecialCharacter) {
        this.requireAtLeastOneSpecialCharacter = requireAtLeastOneSpecialCharacter;
    }

}
