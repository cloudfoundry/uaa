/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.account;

import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

public class PasswordConfirmationValidation {
    private final String password;
    private final String passwordConfirmation;
    private final String email;

    public PasswordConfirmationValidation(String email, String password, String passwordConfirmation) {
        this.email = email;
        this.password = password;
        this.passwordConfirmation = passwordConfirmation;
    }

    public PasswordConfirmationValidation(String password, String passwordConfirmation) {
        this(null, password, passwordConfirmation);
    }

    public boolean valid() {
        return StringUtils.hasText(password) && StringUtils.hasText(passwordConfirmation) && password.equals(passwordConfirmation);
    }

    public void throwIfNotValid() {
        if (!valid()) {
            throw new PasswordConfirmationException(getMessageCode(), getEmail());
        }
    }

    public String getMessageCode() {
        return "form_error";
    }

    public String getEmail() {
        return email;
    }

    public static class PasswordConfirmationException extends AuthenticationException {
        private final String messageCode;
        private final String email;

        public PasswordConfirmationException(String messageCode, String email) {
            super("Passwords do not match for:" + email);
            this.messageCode = messageCode;
            this.email = email;
        }

        public String getMessageCode() {
            return messageCode;
        }

        public String getEmail() {
            return email;
        }
    }
}
