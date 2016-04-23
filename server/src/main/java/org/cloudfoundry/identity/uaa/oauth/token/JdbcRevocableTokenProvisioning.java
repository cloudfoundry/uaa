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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

public class JdbcRevocableTokenProvisioning implements RevocableTokenProvisioning, SystemDeletable {

    protected JdbcTemplate jdbcTemplate;

    protected final static String FIELDS = "token_id,client_id,user_id,format,response_type,issued_at,expires_at,scope,data,identity_zone_id";
    protected static final String UPDATE_FIELDS = FIELDS.substring(FIELDS.indexOf(',')+1, FIELDS.lastIndexOf(',')).replace(",","=?,") + "=?";
    protected final static String TABLE = "revocable_tokens";
    protected final static String GET_QUERY = "SELECT " + FIELDS +" FROM "+TABLE + " WHERE token_id=? AND identity_zone_id=?";
    protected final static String UPDATE_QUERY = "UPDATE "+TABLE+" SET "+UPDATE_FIELDS+" WHERE token_id=? and identity_zone_id=?";
    protected final static String INSERT_QUERY = "INSERT INTO " + TABLE + " ("+FIELDS+") VALUES (?,?,?,?,?,?,?,?,?,?)";
    protected final static String DELETE_QUERY = "DELETE FROM " + TABLE + " WHERE token_id=? and identity_zone_id=?";
    protected final static String DELETE_EXPIRED_QUERY = "DELETE FROM " + TABLE + " WHERE expires_at < ?";
    protected final static String DELETE_BY_ZONE_QUERY = "DELETE FROM " + TABLE + " WHERE identity_zone_id=?";


    protected static final Log logger = LogFactory.getLog(JdbcRevocableTokenProvisioning.class);
    protected final RowMapper<RevocableToken> rowMapper;
    protected final JdbcTemplate template;

    protected AtomicLong lastExpiredCheck = new AtomicLong(0);
    protected long expirationCheckInterval = 30000; //30 seconds

    protected JdbcRevocableTokenProvisioning(JdbcTemplate jdbcTemplate) {
        this.rowMapper =  new RevocableTokenRowMapper();
        this.template = jdbcTemplate;
    }

    @Override
    public List<RevocableToken> retrieveAll() {
        return null;
    }


    public RevocableToken retrieve(String id, boolean checkExpired) {
        if (checkExpired) {
            checkExpired();
        }
        RevocableToken result = template.queryForObject(GET_QUERY, rowMapper, id, IdentityZoneHolder.get().getId());
        if (checkExpired && result.getExpiresAt() < System.currentTimeMillis()) {
            delete(id, 0);
            throw new EmptyResultDataAccessException("Token expired.", 1);
        }
        return result;
    }

    @Override
    public RevocableToken retrieve(String id) {
        return retrieve(id, true);
    }

    @Override
    public RevocableToken create(RevocableToken t) {
        String zoneId = IdentityZoneHolder.get().getId();
        template.update(INSERT_QUERY,
                        t.getTokenId(),
                        t.getClientId(),
                        t.getUserId(),
                        t.getFormat(),
                        t.getResponseType().toString(),
                        t.getIssuedAt(),
                        t.getExpiresAt(),
                        t.getScope(),
                        t.getValue(),
                        zoneId);
        return retrieve(t.getTokenId(), false);
    }

    @Override
    public RevocableToken update(String id, RevocableToken t) {
        String zoneId = IdentityZoneHolder.get().getId();
        template.update(UPDATE_QUERY,
                        t.getClientId(),
                        t.getUserId(),
                        t.getFormat(),
                        t.getResponseType().toString(),
                        t.getIssuedAt(),
                        t.getExpiresAt(),
                        t.getScope(),
                        t.getValue(),
                        id,
                        zoneId);
        return retrieve(id, false);
    }

    @Override
    public RevocableToken delete(String id, int version) {
        RevocableToken previous = retrieve(id, false);
        template.update(DELETE_QUERY, id, IdentityZoneHolder.get().getId());
        return previous;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return template.update(DELETE_BY_ZONE_QUERY, IdentityZoneHolder.get().getId());
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        return 0;
    }

    @Override
    public Log getLogger() {
        return logger;
    }

    public long getExpirationCheckInterval() {
        return expirationCheckInterval;
    }

    public void setExpirationCheckInterval(long expirationCheckInterval) {
        this.expirationCheckInterval = expirationCheckInterval;
    }

    public void checkExpired() {
        long now = System.currentTimeMillis();
        if ((now-lastExpiredCheck.getAndSet(now)) > getExpirationCheckInterval()) {
            int removed = template.update(DELETE_EXPIRED_QUERY, now);
            logger.debug("Removed "+removed+" expired revocable tokens.");
        }

    }

    protected static final class RevocableTokenRowMapper implements RowMapper<RevocableToken> {

        @Override
        public RevocableToken mapRow(ResultSet rs, int rowNum) throws SQLException {
            int pos = 1;

            RevocableToken revocableToken = new RevocableToken();
            revocableToken.setTokenId(rs.getString(pos++));
            revocableToken.setClientId(rs.getString(pos++));
            revocableToken.setUserId(rs.getString(pos++));
            revocableToken.setFormat(rs.getString(pos++));
            String responseType = rs.getString(pos++);
            if(StringUtils.hasText(responseType)) {
                revocableToken.setResponseType(RevocableToken.TokenType.valueOf(responseType));
            }
            revocableToken.setIssuedAt(rs.getLong(pos++));
            revocableToken.setExpiresAt(rs.getLong(pos++));
            revocableToken.setScope(rs.getString(pos++));
            revocableToken.setValue(rs.getString(pos++));
            revocableToken.setZoneId(rs.getString(pos++));
            return revocableToken;
        }
    }
}
