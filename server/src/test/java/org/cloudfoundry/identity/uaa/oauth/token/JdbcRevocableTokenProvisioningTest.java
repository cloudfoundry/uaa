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
package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Before;
import org.junit.Test;

import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.*;
import static org.junit.Assert.*;
import static org.springframework.util.StringUtils.hasText;

public class JdbcRevocableTokenProvisioningTest extends JdbcTestBase {
    public static final String INSERT_SQL_QUERY = "INSE";
    JdbcRevocableTokenProvisioning dao;

    @Before
    public void setUp() {
        dao = new JdbcRevocableTokenProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter));
    }

    @Test
    public void insertToken() throws Exception {
        RevocableToken token = new RevocableToken();
        token.setTokenId("test-token-id");
        token.setClientId("test-client-id");
        token.setResponseType(TOKEN);
        token.setIssuedAt(1457745498);
        token.setExpiresAt(1457755498);
        token.setValue("some-token");

        RevocableToken revocableToken = dao.create(token);

        assertNotNull(revocableToken);
        assertNotNull(revocableToken.getTokenId());
        assertEquals(token.getTokenId(), revocableToken.getTokenId());
    }

    @Test
    public void testUpdate() throws Exception {

    }

    @Test
    public void testDelete() throws Exception {

    }

    @Test
    public void testDeleteByIdentityZone() throws Exception {

    }

    @Test
    public void testDeleteByOrigin() throws Exception {

    }

    @Test
    public void testValidateGroup() throws Exception {

    }
}