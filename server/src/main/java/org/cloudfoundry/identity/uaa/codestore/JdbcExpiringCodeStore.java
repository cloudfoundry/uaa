/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicLong;

@Component(value = "codeStore")
@DependsOnDatabaseInitialization
public class JdbcExpiringCodeStore implements ExpiringCodeStore {

    public static final String tableName = "expiring_code_store";
    public static final String fields = "code, expiresat, data, intent, identity_zone_id";

    protected static final String insert = "insert into " + tableName + " (" + fields + ") values (?,?,?,?,?)";
    protected static final String delete = "delete from " + tableName + " where code = ? and identity_zone_id = ?";
    protected static final String deleteIntent = "delete from " + tableName + " where intent = ? and identity_zone_id = ?";
    protected static final String deleteExpired = "delete from " + tableName + " where expiresat < ?";

    private static final JdbcExpiringCodeMapper rowMapper = new JdbcExpiringCodeMapper();

    protected static final String selectAllFields = "select " + fields + " from " + tableName + " where code = ? and identity_zone_id = ?";

    private Logger logger = LoggerFactory.getLogger(getClass());

    private RandomValueStringGenerator generator = new RandomValueStringGenerator(32);

    private JdbcTemplate jdbcTemplate;

    private TimeService timeService;

    private AtomicLong lastExpired = new AtomicLong();
    private long expirationInterval = 60 * 1_000L; // once a minute

    public long getExpirationInterval() {
        return expirationInterval;
    }

    public void setExpirationInterval(long expirationInterval) {
        this.expirationInterval = expirationInterval;
    }

    public JdbcExpiringCodeStore(DataSource dataSource, TimeService timeService) {
        setDataSource(dataSource);
        setTimeService(timeService);
    }

    protected void setDataSource(DataSource dataSource) {
        jdbcTemplate = new JdbcTemplate(dataSource);
    }

    protected void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }

    @Override
    public ExpiringCode generateCode(String data, Timestamp expiresAt, String intent, String zoneId) {
        cleanExpiredEntries();

        if (data == null || expiresAt == null) {
            throw new NullPointerException();
        }

        if (expiresAt.getTime() < timeService.getCurrentTimeMillis()) {
            throw new IllegalArgumentException();
        }

        int count = 0;
        while (count < 3) {
            count++;
            String code = generator.generate();
            try {
                int update = jdbcTemplate.update(insert, code, expiresAt.getTime(), data, intent, zoneId);
                if (update == 1) {
                    return new ExpiringCode(code, expiresAt, data, intent);
                } else {
                    logger.warn("Unable to store expiring code:{}", code);
                }
            } catch (DataIntegrityViolationException x) {
                if (count == 3) {
                    throw x;
                }
            }
        }

        return null;
    }

    @Override
    public ExpiringCode peekCode(String code, String zoneId) {
        cleanExpiredEntries();

        if (code == null) {
            throw new NullPointerException();
        }

        try {
            ExpiringCode expiringCode = jdbcTemplate.queryForObject(selectAllFields, rowMapper, code, zoneId);
            if (expiringCode != null && expiringCode.getExpiresAt().getTime() < timeService.getCurrentTimeMillis()) {
                expiringCode = null;
            }
            return expiringCode;
        } catch (EmptyResultDataAccessException x) {
            return null;
        }
    }

    @Override
    public ExpiringCode retrieveCode(String code, String zoneId) {
        cleanExpiredEntries();

        if (code == null) {
            throw new NullPointerException();
        }

        try {
            ExpiringCode expiringCode = jdbcTemplate.queryForObject(selectAllFields, rowMapper, code, zoneId);
            if (expiringCode != null) {
                jdbcTemplate.update(delete, code, zoneId);
            }
            if (expiringCode != null && expiringCode.getExpiresAt().getTime() < timeService.getCurrentTimeMillis()) {
                expiringCode = null;
            }
            return expiringCode;
        } catch (EmptyResultDataAccessException x) {
            return null;
        }
    }

    @Override
    public void setGenerator(RandomValueStringGenerator generator) {
        this.generator = generator;
    }

    @Override
    public void expireByIntent(String intent, String zoneId) {
        Assert.hasText(intent, "must have text; it must not be null, empty, or blank");

        jdbcTemplate.update(deleteIntent, intent, zoneId);
    }

    public int cleanExpiredEntries() {
        long now = timeService.getCurrentTimeMillis();
        long lastCheck = lastExpired.get();

        if ((now - lastCheck) > expirationInterval && lastExpired.compareAndSet(lastCheck, now)) {
            int count = jdbcTemplate.update(deleteExpired, now);
            logger.debug("Expiring code sweeper complete, deleted {} entries.", count);
            return count;
        }

        return 0;
    }

    protected static class JdbcExpiringCodeMapper implements RowMapper<ExpiringCode> {

        @Override
        public ExpiringCode mapRow(ResultSet rs, int rowNum) throws SQLException {
            String code = rs.getString("code");
            Timestamp expiresAt = new Timestamp(rs.getLong("expiresat"));
            String intent = rs.getString("intent");
            String data = rs.getString("data");
            return new ExpiringCode(code, expiresAt, data, intent);
        }

    }

}
