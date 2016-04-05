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

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

public class JdbcRevocableTokenProvisioningTest extends JdbcTestBase {

    JdbcRevocableTokenProvisioning dao;
    private RevocableToken token;
    private String tokenId;
    private long issuedAt;
    private String clientId;
    private char[] value;
    private String scope;
    private String userId;
    private String format;

    @Before
    public void createData() {
        value = new char[100*1024];
        Arrays.fill(value, 'X');
        dao = new JdbcRevocableTokenProvisioning(jdbcTemplate);
        tokenId = "test-token-id";
        issuedAt = System.currentTimeMillis() + 10000;
        clientId = "test-client-id";
        scope = "test1,test2";
        userId = "user-id";
        format = "format";
        token = new RevocableToken()
            .setTokenId(tokenId)
            .setClientId(clientId)
            .setResponseType(ACCESS_TOKEN)
            .setIssuedAt(issuedAt)
            .setExpiresAt(issuedAt)
            .setValue(new String(value))
            .setScope(scope)
            .setFormat(format)
            .setUserId(userId);

    }

    @After
    public void clear() {
        IdentityZoneHolder.clear();
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
        RevocableToken revocableToken = dao.create(token);
        assertNotNull(revocableToken);
        assertNotNull(revocableToken.getTokenId());
        assertEquals(token.getTokenId(), revocableToken.getTokenId());
        assertEquals(token.getClientId(), revocableToken.getClientId());
        assertEquals(token.getExpiresAt(), revocableToken.getExpiresAt());
        assertEquals(token.getIssuedAt(), revocableToken.getIssuedAt());
        assertEquals(token.getFormat(), revocableToken.getFormat());
        assertEquals(token.getScope(), revocableToken.getScope());
        assertEquals(token.getValue(), revocableToken.getValue());
        assertEquals(token.getTokenId(), revocableToken.getTokenId());
        assertEquals(token.getResponseType(), revocableToken.getResponseType());
        assertEquals(IdentityZoneHolder.get().getId(), revocableToken.getZoneId());

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
        assertNotNull(revocableToken);
        assertNotNull(revocableToken.getTokenId());
        assertEquals(toUpdate.getTokenId(), revocableToken.getTokenId());
        assertEquals(toUpdate.getClientId(), revocableToken.getClientId());
        assertEquals(toUpdate.getExpiresAt(), revocableToken.getExpiresAt());
        assertEquals(toUpdate.getIssuedAt(), revocableToken.getIssuedAt());
        assertEquals(toUpdate.getFormat(), revocableToken.getFormat());
        assertEquals(toUpdate.getScope(), revocableToken.getScope());
        assertEquals(toUpdate.getValue(), revocableToken.getValue());
        assertEquals(toUpdate.getTokenId(), revocableToken.getTokenId());
        assertEquals(toUpdate.getResponseType(), revocableToken.getResponseType());
        assertEquals(IdentityZoneHolder.get().getId(), revocableToken.getZoneId());
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