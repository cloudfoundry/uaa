/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class InvalidClientSecretExceptionTests {
    @Test
    public void getMessagesAsOneString() throws Exception {
        String msg1 = "Message 1.";
        String msg2 = "Message 2.";
        InvalidClientSecretException exception = new InvalidClientSecretException(Arrays.asList(msg1,msg2));
        assertEquals(msg1+" "+msg2, exception.getMessagesAsOneString());
        assertEquals(msg1+" "+msg2, exception.getMessage());
    }

}