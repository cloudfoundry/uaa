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
package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class UaaUserEditorTests {
    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    private static final String UNM = testAccounts.getUserName();
    private static final String PWD = testAccounts.getPassword();
    private static final String EMAIL = "marissa@test.org";
    private static final String FNM = "Marissa";
    private static final String LNM = "Bloggs";
    private static final String AUTH_1 = "uaa.admin,dash.user";
    private static final String AUTH_2 = "openid";

    @Test
    void shortFormat() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("%s|%s".formatted(UNM, PWD));
        validate((UaaUser) editor.getValue(), UNM, PWD, UNM, null, null, null);
    }

    @Test
    void shortFormatWithAuthorities() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("%s|%s|%s".formatted(UNM, PWD, AUTH_1));
        validate((UaaUser) editor.getValue(), UNM, PWD, UNM, null, null, AUTH_1.split(","));

        editor.setAsText("%s|%s|%s".formatted(UNM, PWD, AUTH_2));
        validate((UaaUser) editor.getValue(), UNM, PWD, UNM, null, null, AUTH_2.split(","));
    }

    @Test
    void longFormat() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("%s|%s|%s|%s|%s".formatted(UNM, PWD, EMAIL, FNM, LNM));
        validate((UaaUser) editor.getValue(), UNM, PWD, EMAIL, FNM, LNM, null);
    }

    @Test
    void longFormatWithAuthorities() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("%s|%s|%s|%s|%s|%s".formatted(UNM, PWD, EMAIL, FNM, LNM, AUTH_1));
        validate((UaaUser) editor.getValue(), UNM, PWD, EMAIL, FNM, LNM, AUTH_1.split(","));

        editor.setAsText("%s|%s|%s|%s|%s|%s".formatted(UNM, PWD, EMAIL, FNM, LNM, AUTH_2));
        validate((UaaUser) editor.getValue(), UNM, PWD, EMAIL, FNM, LNM, AUTH_2.split(","));
    }

    @Test
    void invalidFormat() {
        UaaUserEditor editor = new UaaUserEditor();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> editor.setAsText("%s|%s|%s|%s".formatted(UNM, PWD, FNM, LNM)));
    }

    @Test
    void authorities() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("marissa|koala|marissa@test.org|Marissa|Bloggs|uaa.admin");
        UaaUser user = (UaaUser) editor.getValue();
        assertThat(user.getAuthorities()).isEqualTo(UaaAuthority.ADMIN_AUTHORITIES);
    }

    @Test
    void origin() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("marissa|koala|marissa@test.org|Marissa|Bloggs|uaa.admin|origin");
        UaaUser user = (UaaUser) editor.getValue();
        assertThat(user.getOrigin()).isEqualTo("origin");
    }

    @Test
    void usernameOnly() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("marissa");
        UaaUser user = (UaaUser) editor.getValue();
        validate(user, UNM, null, UNM, null, null, null);
    }

    private void validate(UaaUser user, String expectedUnm, String expectedPwd, String expectedEmail,
                          String expectedFnm, String expectedLnm, String[] expectedAuth) {
        assertThat(user.getUsername()).isEqualTo(expectedUnm);
        assertThat(user.getPassword()).isEqualTo(expectedPwd);
        assertThat(user.getEmail()).isEqualTo(expectedEmail);
        assertThat(user.getGivenName()).isEqualTo(expectedFnm);
        assertThat(user.getFamilyName()).isEqualTo(expectedLnm);
        assertThat(user.getAuthorities().toString()).contains("uaa.user");
        if (expectedAuth != null) {
            for (String auth : expectedAuth) {
                assertThat(user.getAuthorities().toString()).contains(auth);
            }
        }
    }

}
