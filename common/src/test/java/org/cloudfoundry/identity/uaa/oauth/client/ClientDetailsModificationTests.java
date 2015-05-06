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

package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * Created by fhanik on 5/5/15.
 */
public class ClientDetailsModificationTests {

    @Test
    public void testClientDetailsModificationDeserialize() throws Exception {
        String data = "{\"scope\":\n" +
            "        [\"bar\",\"foo\",\"oauth.approvals\"],\n" +
            "        \"client_id\":\"Kn30XB\",\n" +
            "        \"resource_ids\":[\"none\"],\n" +
            "        \"authorized_grant_types\":[\"password\",\"refresh_token\"],\n" +
            "        \"autoapprove\":[],\n" +
            "        \"action\":\"none\",\n" +
            "        \"approvals_deleted\":true,\n" +
            "        \"authorities\":[\"uaa.none\"],\n" +
            "        \"action\":\"none\",\n" +
            "        \"foo\":[\"bar\"],\n" +
            "        \"lastModified\":1430849491767\n" +
            "    }";

        ClientDetailsModification details = JsonUtils.readValue(data, ClientDetailsModification.class);
        assertTrue(details.isApprovalsDeleted());

    }
}