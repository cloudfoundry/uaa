/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.StringUtils;

import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UaaTokenUtilsTest {

    @Test
    public void testRevocationHash() throws Exception {
        List<String> salts = new LinkedList<>();
        for (int i=0; i<3; i++) {
            salts.add(new RandomValueStringGenerator().generate());
        }
        String hash1 = UaaTokenUtils.getRevocationHash(salts);
        String hash2 = UaaTokenUtils.getRevocationHash(salts);
        assertFalse("Hash 1 should not be empty",StringUtils.isEmpty(hash1));
        assertFalse("Hash 2 should not be empty", StringUtils.isEmpty(hash2));
        assertEquals(hash1, hash2);
    }

    @Test
    public void isJwtToken() {

        RandomValueStringGenerator generator = new RandomValueStringGenerator(36);
        String regular = generator.generate();
        String jwt = generator.generate() + "." + generator.generate() + "." + generator.generate();
        assertFalse(UaaTokenUtils.isJwtToken(regular));
        assertTrue(UaaTokenUtils.isJwtToken(jwt));

    }
}