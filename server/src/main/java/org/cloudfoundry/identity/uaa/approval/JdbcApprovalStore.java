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
package org.cloudfoundry.identity.uaa.approval;

import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;

public class JdbcApprovalStore implements ApprovalStore, ApplicationEventPublisherAware, SystemDeletable {

    private final JdbcTemplate jdbcTemplate;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final RowMapper<Approval> rowMapper = new AuthorizationRowMapper();

    private static final String TABLE_NAME = "authz_approvals";

    private static final String FIELDS = "user_id,client_id,scope,expiresAt,status,lastModifiedAt,identity_zone_id";

    private static final String ADD_AUTHZ_SQL =
            "insert into %s ( %s ) values (?,?,?,?,?,?,?)".formatted(
                    TABLE_NAME,
                    FIELDS);

    private static final String REFRESH_AUTHZ_SQL =
            "update %s set lastModifiedAt=?, expiresAt=?, status=? where user_id=? and client_Id=? and scope=? and identity_zone_id=?".formatted(
                    TABLE_NAME);

    private static final String GET_AUTHZ_SQL = "select %s from %s".formatted(FIELDS, TABLE_NAME);

    private static final String DELETE_AUTHZ_SQL = "delete from %s".formatted(TABLE_NAME);

    private static final String EXPIRE_AUTHZ_SQL = "update %s set expiresAt = :expiry".formatted(TABLE_NAME);

    protected static final String DELETE_ZONE_APPROVALS = "delete from authz_approvals where identity_zone_id = ?";

    protected static final String DELETE_CLIENT_APPROVALS = "delete from authz_approvals where client_id = ? and identity_zone_id = ?";

    protected static final String DELETE_USER_APPROVALS = "delete from authz_approvals where user_id = ? and identity_zone_id = ?";

    public static final String DELETE_OF_USER_APPROVALS_BY_PROVIDER = "delete from authz_approvals where user_id in (select id from users where origin = ? and identity_zone_id = ?)";


    private boolean handleRevocationsAsExpiry;
    private ApplicationEventPublisher applicationEventPublisher;

    public JdbcApprovalStore(JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate, "jdbcTemplate is required");
        this.jdbcTemplate = jdbcTemplate;
    }

    public void setHandleRevocationsAsExpiry(boolean handleRevocationsAsExpiry) {
        this.handleRevocationsAsExpiry = handleRevocationsAsExpiry;
    }

    public boolean refreshApproval(final Approval approval, final String zoneId) {
        if (logger.isDebugEnabled()) {
            logger.debug("refreshing approval: [{}]", UaaStringUtils.getCleanedUserControlString(approval.toString()));
        }
        int refreshed = jdbcTemplate.update(REFRESH_AUTHZ_SQL, ps -> {
            ps.setTimestamp(1, new Timestamp(approval.getLastUpdatedAt().getTime()));
            ps.setTimestamp(2, new Timestamp(approval.getExpiresAt().getTime()));
            ps.setString(3, (approval.getStatus() == null ? APPROVED : approval.getStatus()).toString());
            ps.setString(4, approval.getUserId());
            ps.setString(5, approval.getClientId());
            ps.setString(6, approval.getScope());
            ps.setString(7, zoneId);
        });
        if (refreshed != 1) {
            throw new DataIntegrityViolationException("Attempt to refresh non-existent authorization");
        }
        return true;
    }

    @Override
    public boolean addApproval(final Approval approval, final String zoneId) {
        if (logger.isDebugEnabled()) {
            logger.debug("adding approval: [{}]", UaaStringUtils.getCleanedUserControlString(approval.toString()));
        }
        try {
            refreshApproval(approval, zoneId); // try to refresh the approval
        } catch (DataIntegrityViolationException ex) { // could not find the
            // approval. add it.
            int count = jdbcTemplate.update(ADD_AUTHZ_SQL, ps -> {
                ps.setString(1, approval.getUserId());
                ps.setString(2, approval.getClientId());
                ps.setString(3, approval.getScope());
                ps.setTimestamp(4, new Timestamp(approval.getExpiresAt().getTime()));
                ps.setString(5, (approval.getStatus() == null ? APPROVED : approval.getStatus()).toString());
                ps.setTimestamp(6, new Timestamp(approval.getLastUpdatedAt().getTime()));
                ps.setString(7, zoneId);
            });
            if (count == 0) {
                throw new EmptyResultDataAccessException("Approval add failed", 1);
            }
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        publish(new ApprovalModifiedEvent(approval, authentication));
        return true;
    }

    @Override
    public boolean revokeApproval(Approval approval, final String zoneId) {
        String sql = handleRevocationsAsExpiry ? EXPIRE_AUTHZ_SQL : DELETE_AUTHZ_SQL;
        sql += " WHERE user_id = ? AND client_id = ? AND scope = ? AND identity_zone_id = ?";
        int count = jdbcTemplate.update(sql, ps -> {
            int pos = 1;
            ps.setString(pos++, approval.getUserId());
            ps.setString(pos++, approval.getClientId());
            ps.setString(pos++, approval.getScope());
            ps.setString(pos++, zoneId);
        });
        return count > 0;
    }

    @Override
    public boolean revokeApprovalsForUser(String userId, final String zoneId) {
        String sql = handleRevocationsAsExpiry ? EXPIRE_AUTHZ_SQL : DELETE_AUTHZ_SQL;
        sql += " WHERE user_id = ? AND identity_zone_id = ?";
        int count = jdbcTemplate.update(sql, ps -> {
            int pos = 1;
            ps.setString(pos++, userId);
            ps.setString(pos++, zoneId);
        });
        return count > 0;
    }

    @Override
    public boolean revokeApprovalsForClient(String clientId, final String zoneId) {
        String sql = handleRevocationsAsExpiry ? EXPIRE_AUTHZ_SQL : DELETE_AUTHZ_SQL;
        sql += " WHERE client_id = ? AND identity_zone_id = ?";
        int count = jdbcTemplate.update(sql, ps -> {
            int pos = 1;
            ps.setString(pos++, clientId);
            ps.setString(pos++, zoneId);
        });
        return count > 0;
    }

    @Override
    public boolean revokeApprovalsForClientAndUser(String clientId, String userId, final String zoneId) {
        String sql = handleRevocationsAsExpiry ? EXPIRE_AUTHZ_SQL : DELETE_AUTHZ_SQL;
        sql += " WHERE user_id = ? AND client_id = ? AND identity_zone_id = ?";
        int count = jdbcTemplate.update(sql, ps -> {
            int pos = 1;
            ps.setString(pos++, userId);
            ps.setString(pos++, clientId);
            ps.setString(pos++, zoneId);
        });
        return count > 0;
    }

    public boolean purgeExpiredApprovals() {
        logger.debug("Purging expired approvals from database");
        try {
            int deleted = jdbcTemplate.update(DELETE_AUTHZ_SQL + " where expiresAt <= ?",
                    //PreparedStatementSetter
                    ps -> ps.setTimestamp(1, new Timestamp(new Date().getTime()))
            );
            logger.debug("{} expired approvals deleted", deleted);
        } catch (DataAccessException ex) {
            logger.error("Error purging expired approvals", ex);
            return false;
        }
        return true;
    }

    @Override
    public List<Approval> getApprovalsForUser(String userId, final String zoneId) {
        String sql = GET_AUTHZ_SQL + " WHERE user_id = ? AND identity_zone_id = ?";
        return jdbcTemplate.query(
                sql,
                ps -> {
                    int pos = 1;
                    ps.setString(pos++, userId);
                    ps.setString(pos++, zoneId);
                },
                rowMapper
        );
    }

    @Override
    public List<Approval> getApprovalsForClient(String clientId, final String zoneId) {
        String sql = GET_AUTHZ_SQL + " WHERE client_id = ? AND identity_zone_id = ?";
        return jdbcTemplate.query(
                sql,
                ps -> {
                    int pos = 1;
                    ps.setString(pos++, clientId);
                    ps.setString(pos++, zoneId);
                },
                rowMapper
        );
    }

    @Override
    public List<Approval> getApprovals(String userId, String clientId, final String zoneId) {
        String sql = GET_AUTHZ_SQL + " WHERE user_id = ? AND client_id = ? AND identity_zone_id = ?";
        return jdbcTemplate.query(
                sql,
                ps -> {
                    int pos = 1;
                    ps.setString(pos++, userId);
                    ps.setString(pos++, clientId);
                    ps.setString(pos++, zoneId);
                },
                rowMapper
        );
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    public void publish(ApplicationEvent event) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(event);
        }
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        int approvalCount = jdbcTemplate.update(DELETE_ZONE_APPROVALS, zoneId);
        getLogger().debug("Deleted zone approvals '{}' and count:{}", zoneId, approvalCount);
        return approvalCount;
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        int approvalCount = jdbcTemplate.update(DELETE_OF_USER_APPROVALS_BY_PROVIDER, origin, zoneId);
        getLogger().debug("Deleted provider approvals '{}'/{} and count:{}", origin, zoneId, approvalCount);
        return approvalCount;
    }

    @Override
    public int deleteByClient(String clientId, String zoneId) {
        int approvalCount = jdbcTemplate.update(DELETE_CLIENT_APPROVALS, clientId, zoneId);
        getLogger().debug("Deleted client '{}' and {} approvals", clientId, approvalCount);
        return approvalCount;
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        int approvalCount = jdbcTemplate.update(DELETE_USER_APPROVALS, userId, zoneId);
        getLogger().debug("Deleted user '{}' and {} approvals", userId, approvalCount);
        return approvalCount;
    }

    @Override
    public Logger getLogger() {
        return logger;
    }

    private static class AuthorizationRowMapper implements RowMapper<Approval> {
        @Override
        public Approval mapRow(ResultSet rs, int rowNum) throws SQLException {
            String userId = rs.getString(1);
            String clientId = rs.getString(2);
            String scope = rs.getString(3);
            Date expiresAt = rs.getTimestamp(4);
            String status = rs.getString(5);
            Date lastUpdatedAt = rs.getTimestamp(6);

            return new Approval()
                    .setUserId(userId)
                    .setClientId(clientId)
                    .setScope(scope)
                    .setExpiresAt(expiresAt)
                    .setStatus(ApprovalStatus.valueOf(status))
                    .setLastUpdatedAt(lastUpdatedAt);
        }
    }
}
