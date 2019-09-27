/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider.ldap;

import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.ldap.model.password.PasswordUtil;

public class DynamicPasswordComparator implements org.springframework.security.crypto.password.PasswordEncoder {

    public DynamicPasswordComparator() {
    }

    public boolean comparePasswords(byte[] received, byte[] stored) {
        return PasswordUtil.compareCredentials(received, stored);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        throw new UnsupportedOperationException();
    }

    public static void main(String[] args) {
        LdapSecurityConstants test = PasswordUtil.findAlgorithm("{sha}YaE1CJ6sVhov987e77A5db7QAPg=".getBytes());
        System.out.println(test);
    }

}
