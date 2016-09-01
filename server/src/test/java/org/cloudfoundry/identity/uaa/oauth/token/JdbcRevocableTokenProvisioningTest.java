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

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class JdbcRevocableTokenProvisioningTest extends JdbcTestBase {

    JdbcRevocableTokenProvisioning dao;
    private RevocableToken expected;
    private String tokenId;
    private long issuedAt;
    private String clientId;
    private char[] value;
    private String scope;
    private String userId;
    private String format;
    private Random random = new Random(System.currentTimeMillis());
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();


    @Before
    public void createData() {
        createData("test-token-id", "test-user-id", "test-client-id");
    }

    public void createData(String tokenId, String userId, String clientId) {
        value = new char[100*1024];
        Arrays.fill(value, 'X');
        dao = new JdbcRevocableTokenProvisioning(jdbcTemplate);
        this.tokenId = tokenId;
        this.clientId = clientId;
        this.userId = userId;
        issuedAt = System.currentTimeMillis() + random.nextInt(10000);
        scope = "test1,test2";
        format = "format";
        expected = new RevocableToken()
            .setTokenId(tokenId)
            .setClientId(clientId)
            .setResponseType(ACCESS_TOKEN)
            .setIssuedAt(issuedAt)
            .setExpiresAt(issuedAt)
            .setValue(new String(value))
            .setScope(scope)
            .setFormat(format)
            .setUserId(userId)
            .setZoneId(IdentityZoneHolder.get().getId());

    }

    @After
    public void clear() {
        IdentityZoneHolder.clear();
        jdbcTemplate.update("DELETE FROM revocable_tokens");
    }

    @Test
    public void retrieve_all_returns_nothing() {
        assertNull(dao.retrieveAll());
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void testNotFound() {
        dao.retrieve(tokenId);
    }

    @Test()
    public void testGetFound() throws Exception {
        insertToken();
        assertNotNull(dao.retrieve(tokenId));
    }

    @Test
    public void testAdd_Duplicate_Fails() throws Exception {
        insertToken();
        try {
            insertToken();
        }catch (DuplicateKeyException x) {}
    }

    @Test()
    public void testGetFound_In_Zone() throws Exception {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("new-zone", "new-zone"));
        insertToken();
        assertNotNull(dao.retrieve(tokenId));
        IdentityZoneHolder.clear();
        try {
            dao.retrieve(tokenId);
        }catch (EmptyResultDataAccessException x){}
    }

    @Test
    public void insertToken() throws Exception {
        RevocableToken actual = dao.create(expected);
        evaluateToken(expected, actual);
    }

    protected void evaluateToken(RevocableToken expected, RevocableToken actual) {
        assertNotNull(actual);
        assertNotNull(actual.getTokenId());
        assertEquals(expected.getTokenId(), actual.getTokenId());
        assertEquals(expected.getClientId(), actual.getClientId());
        assertEquals(expected.getExpiresAt(), actual.getExpiresAt());
        assertEquals(expected.getIssuedAt(), actual.getIssuedAt());
        assertEquals(expected.getFormat(), actual.getFormat());
        assertEquals(expected.getScope(), actual.getScope());
        assertEquals(expected.getValue(), actual.getValue());
        assertEquals(expected.getTokenId(), actual.getTokenId());
        assertEquals(expected.getResponseType(), actual.getResponseType());
        assertEquals(IdentityZoneHolder.get().getId(), actual.getZoneId());
    }

    @Test
    public void listUserTokens() throws Exception {
        listTokens(false);
    }

    @Test(expected = NullPointerException.class)
    public void listUserTokens_Null_ClientId() {
        dao.getUserTokens("userid", null);
    }

    @Test(expected = NullPointerException.class)
    public void listUserTokens_Empty_ClientId() {
        dao.getUserTokens("userid", "");
    }

    @Test
    public void listUserTokenForClient() throws Exception {
        String clientId = "test-client-id";
        String userId = "test-user-id";
        List<RevocableToken> expectedTokens = new ArrayList<>();
        int count = 37;
        RandomValueStringGenerator generator = new RandomValueStringGenerator(36);
        for (int i=0; i<count; i++) {
            createData(generator.generate(), userId, clientId);
            insertToken();
            expectedTokens.add(this.expected);
        }

        for (int i=0; i<count; i++) {
            //create a random record that should not show up
            createData(generator.generate(), generator.generate(), generator.generate());
            insertToken();
        }

        List<RevocableToken> actualTokens = dao.getUserTokens(userId, clientId);
        assertThat(actualTokens, containsInAnyOrder(expectedTokens.toArray()));
    }

    @Test
    public void listClientTokens() throws Exception {
        listTokens(true);
    }

    public void listTokens(boolean client) throws Exception {
        String clientId = "test-client-id";
        String userId = "test-user-id";
        List<RevocableToken> expectedTokens = new ArrayList<>();
        int count = 37;
        RandomValueStringGenerator generator = new RandomValueStringGenerator(36);
        for (int i=0; i<count; i++) {
            if (client) {
                userId = generator.generate();
            } else {
                clientId = generator.generate();
            }
            createData(generator.generate(), userId, clientId);
            insertToken();
            expectedTokens.add(this.expected);
        }

        //create a random record that should not show up
        createData(generator.generate(), generator.generate(), generator.generate());
        insertToken();

        List<RevocableToken> actualTokens = client ? dao.getClientTokens(clientId) : dao.getUserTokens(userId);
        assertThat(actualTokens, containsInAnyOrder(expectedTokens.toArray()));
    }

    @Test
    public void testUpdate() throws Exception {
        char[] data = new char[200*1024];
        Arrays.fill(data, 'Y');
        insertToken();
        RevocableToken toUpdate = dao.retrieve(tokenId);
        long expiresAt = System.currentTimeMillis()+1000;
        String scope = "scope1,scope2,scope3";
        toUpdate.setFormat("format")
            .setExpiresAt(expiresAt)
            .setIssuedAt(expiresAt)
            .setClientId("new-client-id")
            .setScope(scope)
            .setValue(new String(data))
            .setUserId("new-user-id")
            .setZoneId("arbitrary-zone-id")
            .setResponseType(REFRESH_TOKEN);

        RevocableToken revocableToken = dao.update(tokenId, toUpdate);
        evaluateToken(toUpdate, revocableToken);
    }

    @Test
    public void testDelete() throws Exception {
        insertToken();
        dao.retrieve(tokenId);
        dao.delete(tokenId, 8);
        try {
            dao.retrieve(tokenId);
            fail("Token should have been deleted");
        } catch (EmptyResultDataAccessException x) {}

    }

    @Test
    public void ensure_expired_token_is_deleted() throws Exception {
        insertToken();
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=? WHERE token_id=?", System.currentTimeMillis() - 10000, tokenId);
        try {
            dao.retrieve(tokenId);
            fail("Token should have been deleted");
        } catch (EmptyResultDataAccessException x) {}
        assertEquals((int)0, (int)jdbcTemplate.queryForObject("select count(1) from revocable_tokens where token_id=?", Integer.class, tokenId));

    }


    @Test
    public void test_periodic_deletion_of_expired_tokens() throws Exception {
        insertToken();
        expected.setTokenId(new RandomValueStringGenerator().generate());
        insertToken();
        assertEquals(2, (int)jdbcTemplate.queryForObject("select count(1) from revocable_tokens", Integer.class));
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=?", System.currentTimeMillis() - 10000);
        try {
            dao.retrieve(tokenId);
            fail("Token should have been deleted");
        } catch (EmptyResultDataAccessException x) {}
        assertEquals(0, (int)jdbcTemplate.queryForObject("select count(1) from revocable_tokens", Integer.class));
    }

    @Test
    public void testDeleteByIdentityZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone","test-zone");
        IdentityZoneHolder.set(zone);
        insertToken();
        dao.retrieve(tokenId);
        EntityDeletedEvent<IdentityZone> zoneDeleted = new EntityDeletedEvent<>(zone, null);
        dao.onApplicationEvent(zoneDeleted);
        try {
            dao.retrieve(tokenId);
            fail("Token should have been deleted");
        } catch (EmptyResultDataAccessException x) {}
    }

    @Test
    public void testDeleteByOrigin() throws Exception {
        //no op - doesn't affect tokens
    }

}