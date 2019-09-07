/*******************************************************************************
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
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class UaaUserEditorTests {
    private static UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);
    
    private static String unm = testAccounts.getUserName();
    private static String pwd = testAccounts.getPassword();
    private static String email = "marissa@test.org";
    private static String fnm = "Marissa";
    private static String lnm = "Bloggs";
    private static String auth1 = "uaa.admin,dash.user";
    private static String auth2 = "openid";

    @Test
    public void testShortFormat() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText(String.format("%s|%s", unm, pwd));
        validate((UaaUser) editor.getValue(), unm, pwd, unm, null, null, null);
    }

    @Test
    public void testShortFormatWithAuthorities() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText(String.format("%s|%s|%s", unm, pwd, auth1));
        validate((UaaUser) editor.getValue(), unm, pwd, unm, null, null, auth1.split(","));

        editor.setAsText(String.format("%s|%s|%s", unm, pwd, auth2));
        validate((UaaUser) editor.getValue(), unm, pwd, unm, null, null, auth2.split(","));
    }

    @Test
    public void testLongFormat() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText(String.format("%s|%s|%s|%s|%s", unm, pwd, email, fnm, lnm));
        validate((UaaUser) editor.getValue(), unm, pwd, email, fnm, lnm, null);
    }

    @Test
    public void testLongFormatWithAuthorities() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText(String.format("%s|%s|%s|%s|%s|%s", unm, pwd, email, fnm, lnm, auth1));
        validate((UaaUser) editor.getValue(), unm, pwd, email, fnm, lnm, auth1.split(","));

        editor.setAsText(String.format("%s|%s|%s|%s|%s|%s", unm, pwd, email, fnm, lnm, auth2));
        validate((UaaUser) editor.getValue(), unm, pwd, email, fnm, lnm, auth2.split(","));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidFormat() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText(String.format("%s|%s|%s|%s", unm, pwd, fnm, lnm));
    }

    @Test
    public void testAuthorities() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("marissa|koala|marissa@test.org|Marissa|Bloggs|uaa.admin");
        UaaUser user = (UaaUser) editor.getValue();
        assertEquals(UaaAuthority.ADMIN_AUTHORITIES, user.getAuthorities());
    }

    @Test
    public void usernameOnly() {
        UaaUserEditor editor = new UaaUserEditor();
        editor.setAsText("marissa");
        UaaUser user = (UaaUser) editor.getValue();
        validate(user, unm, null, unm, null, null, null);
    }

    private void validate(UaaUser user, String expectedUnm, String expectedPwd, String expectedEmail,
                    String expectedFnm, String expectedLnm, String[] expectedAuth) {
        assertEquals(expectedUnm, user.getUsername());
        assertEquals(expectedPwd, user.getPassword());
        assertEquals(expectedEmail, user.getEmail());
        assertEquals(expectedFnm, user.getGivenName());
        assertEquals(expectedLnm, user.getFamilyName());
        assertTrue(user.getAuthorities().toString().contains("uaa.user"));
        if (expectedAuth != null) {
            for (String auth : expectedAuth) {
                assertTrue(user.getAuthorities().toString().contains(auth));
            }
        }
    }

}
