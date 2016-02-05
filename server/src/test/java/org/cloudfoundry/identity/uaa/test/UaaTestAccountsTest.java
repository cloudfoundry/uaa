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

package org.cloudfoundry.identity.uaa.test;

import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.client.test.TestAccounts;

public class UaaTestAccountsTest extends TestCase {
    
    private TestAccounts testAccounts;
    
    @Before
    public void setUp() throws Exception {
        testAccounts = UaaTestAccounts.standard(null);    
    }
    
    @Test
    public void testGetDefaultUsername() throws Exception {
        assertEquals(UaaTestAccounts.DEFAULT_USERNAME, testAccounts.getUserName());
    }


    @Test
    public void testGetAlternateUsername() throws Exception {
        String property = "uaa.test.username";
        try {
            String username = "marissa2";
            System.setProperty(property, username);
            assertEquals(username, testAccounts.getUserName());
        } finally {
            System.getProperties().remove(property);
        }
    }

    @Test
    public void testGetDefaultPassword() throws Exception {
        assertEquals(UaaTestAccounts.DEFAULT_PASSWORD, testAccounts.getPassword());
    }


    @Test
    public void testGetAlternatePassword() throws Exception {
        String property = "uaa.test.password";
        try {
            String password = "koala2";
            System.setProperty(property, password);
            assertEquals(password, testAccounts.getPassword());
        } finally {
            System.getProperties().remove(property);
        }
    }

}