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
package org.cloudfoundry.identity.uaa.codestore;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicLong;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;

public class JdbcExpiringCodeStore implements ExpiringCodeStore {

    public static final String tableName = "expiring_code_store";
    public static final String fields = "code, expiresat, data, intent";

    public static final String insert = "insert into " + tableName + " (" + fields + ") values (?,?,?,?)";
    public static final String delete = "delete from " + tableName + " where code = ?";
    public static final String deleteIntent = "delete from " + tableName + " where intent = ?";
    public static final String deleteExpired = "delete from " + tableName + " where expiresat < ?";
    public static final String select = "select " + fields + " from " + tableName + " where code = ?";
    public static final String SELECT_BY_EMAIL_AND_CLIENT_ID = "select " + fields + " from " + tableName +
            " where data like '%%\"email\":\"%s\"%%' and data like '%%\"client_id\":\"%s\"%%' ORDER BY expiresat DESC LIMIT 1";

    private Log logger = LogFactory.getLog(getClass());

    private RandomValueStringGenerator generator = new RandomValueStringGenerator(10);

    private JdbcTemplate jdbcTemplate;

    private AtomicLong lastExpired = new AtomicLong();
    private long expirationInterval = 60 * 1000; // once a minute

    public long getExpirationInterval() {
        return expirationInterval;
    }

    public void setExpirationInterval(long expirationInterval) {
        this.expirationInterval = expirationInterval;
    }

    protected JdbcExpiringCodeStore() {
        // package protected for unit tests only
    }

    public JdbcExpiringCodeStore(DataSource dataSource) {
        setDataSource(dataSource);
    }

    public void setDataSource(DataSource dataSource) {
        jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public ExpiringCode generateCode(String data, Timestamp expiresAt, String intent) {
        cleanExpiredEntries();

        if (data == null || expiresAt == null) {
            throw new NullPointerException();
        }

        if (expiresAt.getTime() < System.currentTimeMillis()) {
            throw new IllegalArgumentException();
        }

        int count = 0;
        while (count < 3) {
            count++;
            String code = generator.generate();
            try {
                int update = jdbcTemplate.update(insert, code, expiresAt.getTime(), data, intent);
                if (update == 1) {
                    ExpiringCode expiringCode = new ExpiringCode(code, expiresAt, data, intent);
                    return expiringCode;
                } else {
                    logger.warn("Unable to store expiring code:" + code);
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
    public ExpiringCode retrieveCode(String code) {
        cleanExpiredEntries();

        if (code == null) {
            throw new NullPointerException();
        }

        try {
            ExpiringCode expiringCode = jdbcTemplate.queryForObject(select, new JdbcExpiringCodeMapper(), code);
            try {
                if (expiringCode != null) {
                    jdbcTemplate.update(delete, code);
                }
                if (expiringCode.getExpiresAt().getTime() < System.currentTimeMillis()) {
                    expiringCode = null;
                }
            } finally {
                return expiringCode;
            }
        } catch (EmptyResultDataAccessException x) {
            return null;
        }
    }

    @Override
    public void setGenerator(RandomValueStringGenerator generator) {
        this.generator = generator;
    }

    @Override
    public void expireByIntent(String intent) {
        Assert.hasText(intent);

        jdbcTemplate.update(deleteIntent, intent);
    }

    public int cleanExpiredEntries() {
        long now = System.currentTimeMillis();
        long lastCheck = lastExpired.get();

        if ((now - lastCheck) > expirationInterval && lastExpired.compareAndSet(lastCheck, now)) {
            int count = jdbcTemplate.update(deleteExpired, now);
            logger.debug("Expiring code sweeper complete, deleted " + count + " entries.");
            return count;
        }

        return 0;
    }

    protected static class JdbcExpiringCodeMapper implements RowMapper<ExpiringCode> {

        @Override
        public ExpiringCode mapRow(ResultSet rs, int rowNum) throws SQLException {
            int pos = 1;
            String code = rs.getString(pos++);
            Timestamp expiresAt = new Timestamp(rs.getLong(pos++));
            String data = rs.getString(pos++);
            String intent = rs.getString(pos++);
            return new ExpiringCode(code, expiresAt, data, intent);
        }

    }

}
