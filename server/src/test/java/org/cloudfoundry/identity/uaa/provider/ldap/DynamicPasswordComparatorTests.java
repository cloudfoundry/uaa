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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.util.AssertionErrors.fail;

class DynamicPasswordComparatorTests {
    private final DynamicPasswordComparator comparator = new DynamicPasswordComparator();
    private static final String[] passwords = {
            "test", //plaintext
            "{sha}qUqP5cyxm6YcTAhz05Hph5gvu9M=", //SHA
            "{sha256}n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", //SHA 256
            "{sha384}doQSMg97CqWBL85CjcRwazyuUOAqZMqhangiSb/o78S37xzLEmJV0ZYEff7fF6Cp", //SHA 384
            "{sha512}7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==", //SHA 512
            "{ssha}rO4v/9dub7WYpIrDj7wvb7fNwkOImf1VVJnZpg==", //SSHA
            "{ssha256}zCVpD8Xi4JMmVcaAxi28ak8/xJxQhrg+VT1MJ16hHimXN7orxv6poQ==", //SSHA 256
            "{ssha384}7YxTGbDRHR0XwaDZSLu0dugE0wUgQ5+laFB0xRAvsvH0lC3W2IB0p3C3HQVMfzpQCpyASAjKM3I=", //SSHA 384
            "{ssha512}tD7p1yhvG1aMGKWbxYgkRIwnKYwuDPjdg6DIlkUMn8zWmShQ00Y50LKVE0lW4ubdkx3PYnPS3AM64y/p5P+AOYBsj7vmQxCy", //SSHA 512
            "{md5}CY9rzUYh03PK3k6DJie09g==", //MD5
            "{smd5}Pd3O3i4CelPVsTXKIjnLpZAu00x01cx0", //SMD5
            "{crypt}32nQRBPsx/pq." //CRYPT
    };

    private byte[] getBytes(String s) {
        return s.getBytes();
    }

    @Test
    void comparePasswords() {
        byte[] test = getBytes("test");
        for (String s : passwords) {
            try {
                assertThat(comparator.comparePasswords(test, getBytes(s))).as("Password[" + s + "] should match 'test'").isTrue();
            } catch (Exception e) {
                e.printStackTrace();
                fail("Unsuccessful on password [" + s + "]");
            }
        }
    }

    @Test
    void encodePassword() {
        try {
            comparator.encode("test");
            fail("Method and test not implemented yet.");
        } catch (UnsupportedOperationException ignored) {
        }
    }

    @Test
    void isPasswordValid() {
        try {
            comparator.matches("test", "test");
            fail("Method and test not implemented yet.");
        } catch (UnsupportedOperationException ignored) {
        }

    }
}