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

import org.apache.commons.io.IOUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.Charset;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class IdentityZoneHolderTest {

    @Test
    public void deserialize() {
        final String sampleIdentityZone = getResourceAsString("sampleIdentityZone.json");

        JsonUtils.readValue(sampleIdentityZone, IdentityZone.class);
    }

    private String getResourceAsString(String s) {
        try {
            return IOUtils.toString(getClass().getResourceAsStream(s), Charset.defaultCharset());
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
