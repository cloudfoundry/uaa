/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.user;


import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

public class BCryptPasswordEncoderTest {


    @Test
    public void testSameSaltHash() {
        String salt = BCrypt.gensalt();
        String passwd = "testpassword"+new RandomValueStringGenerator().generate();
        Assert.assertEquals(BCrypt.hashpw(passwd, salt), BCrypt.hashpw(passwd, salt));
    }

    @Test
    public void testEmptyPassword() {

        String passwd = "";
        Assert.assertTrue(new BCryptPasswordEncoder().matches("", new BCryptPasswordEncoder().encode("")));
    }


}
