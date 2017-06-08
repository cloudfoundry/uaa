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
package org.cloudfoundry.identity.uaa.approval;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;

public class JdbcApprovalStore implements ApprovalStore, ApplicationEventPublisherAware, SystemDeletable {

    private final JdbcTemplate jdbcTemplate;

    private final Log logger = LogFactory.getLog(getClass());

    private final RowMapper<Approval> rowMapper = new AuthorizationRowMapper();

    private static final String TABLE_NAME = "authz_approvals";

    private static final String FIELDS = "user_id,client_id,scope,expiresAt,status,lastModifiedAt,identity_zone_id";

    private static final String ADD_AUTHZ_SQL =
        String.format("insert into %s ( %s ) values (?,?,?,?,?,?,?)",
                      TABLE_NAME,
                      FIELDS);

    private static final String REFRESH_AUTHZ_SQL =
        String.format("update %s set lastModifiedAt=?, expiresAt=?, status=? where user_id=? and client_Id=? and scope=? and identity_zone_id=?",
                      TABLE_NAME);

    private static final String GET_AUTHZ_SQL = String.format("select %s from %s", FIELDS, TABLE_NAME);

    private static final String DELETE_AUTHZ_SQL = String.format("delete from %s", TABLE_NAME);

    private static final String EXPIRE_AUTHZ_SQL = String.format("update %s set expiresAt = :expiry", TABLE_NAME);

    protected static final String DELETE_ZONE_APPROVALS = "delete from authz_approvals where identity_zone_id = ?";

    protected static final String DELETE_CLIENT_APPROVALS = "delete from authz_approvals where client_id = ? and identity_zone_id = ?";

    protected static final String DELETE_USER_APPROVALS = "delete from authz_approvals where user_id = ? and identity_zone_id = ?";

    public static final String DELETE_OF_USER_APPROVALS_BY_PROVIDER = "delete from authz_approvals where user_id in (select id from users where identity_zone_id = ? and origin = ?)";


    private boolean handleRevocationsAsExpiry = false;
    private ApplicationEventPublisher applicationEventPublisher;

    public JdbcApprovalStore(JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    public void setHandleRevocationsAsExpiry(boolean handleRevocationsAsExpiry) {
        this.handleRevocationsAsExpiry = handleRevocationsAsExpiry;
    }

    public boolean refreshApproval(final Approval approval, final String zoneId) {
        logger.debug(String.format("refreshing approval: [%s]", approval));
        int refreshed = jdbcTemplate.update(REFRESH_AUTHZ_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setTimestamp(1, new Timestamp(approval.getLastUpdatedAt().getTime()));
                ps.setTimestamp(2, new Timestamp(approval.getExpiresAt().getTime()));
                ps.setString(3, (approval.getStatus() == null ? APPROVED : approval.getStatus()).toString());
                ps.setString(4, approval.getUserId());
                ps.setString(5, approval.getClientId());
                ps.setString(6, approval.getScope());
                ps.setString(7, zoneId);
            }
        });
        if (refreshed != 1) {
            throw new DataIntegrityViolationException("Attempt to refresh non-existent authorization");
        }
        return true;
    }

    @Override
    public boolean addApproval(final Approval approval, final String zoneId) {
        logger.debug(String.format("adding approval: [%s]", approval));
        try {
            refreshApproval(approval, IdentityZoneHolder.get().getId()); // try to refresh the approval
        } catch (DataIntegrityViolationException ex) { // could not find the
            // approval. add it.
            int count = jdbcTemplate.update(ADD_AUTHZ_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, approval.getUserId());
                    ps.setString(2, approval.getClientId());
                    ps.setString(3, approval.getScope());
                    ps.setTimestamp(4, new Timestamp(approval.getExpiresAt().getTime()));
                    ps.setString(5, (approval.getStatus() == null ? APPROVED : approval.getStatus()).toString());
                    ps.setTimestamp(6, new Timestamp(approval.getLastUpdatedAt().getTime()));
                    ps.setString(7, zoneId);
                }
            });
            if (count == 0) throw new EmptyResultDataAccessException("Approval add failed", 1);
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        publish(new ApprovalModifiedEvent(approval, authentication));
        return true;
    }

    @Override
    public boolean revokeApproval(Approval approval, final String zoneId) {
        String sql = handleRevocationsAsExpiry ? EXPIRE_AUTHZ_SQL : DELETE_AUTHZ_SQL;
        sql += " WHERE user_id = ? AND client_id = ? AND scope = ? AND identity_zone_id = ?";
        int count = jdbcTemplate.update(sql, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                ps.setString(pos++, approval.getUserId());
                ps.setString(pos++, approval.getClientId());
                ps.setString(pos++, approval.getScope());
                ps.setString(pos++, zoneId);
            }
        });
        return count > 0;
    }

    @Override
    public boolean revokeApprovalsForUser(String userId, final String zoneId) {
        String sql = handleRevocationsAsExpiry ? EXPIRE_AUTHZ_SQL : DELETE_AUTHZ_SQL;
        sql += " WHERE user_id = ? AND identity_zone_id = ?";
        int count = jdbcTemplate.update(sql, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                ps.setString(pos++, userId);
                ps.setString(pos++, zoneId);
            }
        });
        return count > 0;
    }

    @Override
    public boolean revokeApprovalsForClient(String clientId, final String zoneId) {
        String sql = handleRevocationsAsExpiry ? EXPIRE_AUTHZ_SQL : DELETE_AUTHZ_SQL;
        sql += " WHERE client_id = ? AND identity_zone_id = ?";
        int count = jdbcTemplate.update(sql, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                ps.setString(pos++, clientId);
                ps.setString(pos++, zoneId);
            }
        });
        return count > 0;
    }

    @Override
    public boolean revokeApprovalsForClientAndUser(String clientId, String userId, final String zoneId) {
        String sql = handleRevocationsAsExpiry ? EXPIRE_AUTHZ_SQL : DELETE_AUTHZ_SQL;
        sql += " WHERE user_id = ? AND client_id = ? AND identity_zone_id = ?";
        int count = jdbcTemplate.update(sql, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                ps.setString(pos++, userId);
                ps.setString(pos++, clientId);
                ps.setString(pos++, zoneId);
            }
        });
        return count > 0;
    }

    public boolean purgeExpiredApprovals() {
        logger.debug("Purging expired approvals from database");
        try {
            int deleted = jdbcTemplate.update(DELETE_AUTHZ_SQL + " where expiresAt <= ?",
                                              ps -> { //PreparedStatementSetter
                                                  ps.setTimestamp(1, new Timestamp(new Date().getTime()));
                                              });
            logger.debug(deleted + " expired approvals deleted");
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
            new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    int pos = 1;
                    ps.setString(pos++, userId);
                    ps.setString(pos++, zoneId);
                }
            },
            rowMapper
        );
    }

    @Override
    public List<Approval> getApprovalsForClient(String clientId, final String zoneId) {
        String sql = GET_AUTHZ_SQL + " WHERE client_id = ? AND identity_zone_id = ?";
        return jdbcTemplate.query(
            sql,
            new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    int pos = 1;
                    ps.setString(pos++, clientId);
                    ps.setString(pos++, zoneId);
                }
            },
            rowMapper
        );
    }

    @Override
    public List<Approval> getApprovals(String userId, String clientId, final String zoneId) {
        String sql = GET_AUTHZ_SQL + " WHERE user_id = ? AND client_id = ? AND identity_zone_id = ?";
        return jdbcTemplate.query(
            sql,
            new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    int pos = 1;
                    ps.setString(pos++, userId);
                    ps.setString(pos++, clientId);
                    ps.setString(pos++, zoneId);
                }
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
        getLogger().debug(String.format("Deleted zone approvals '%s' and count:%s", zoneId, approvalCount));
        return approvalCount;
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        int approvalCount = jdbcTemplate.update(DELETE_OF_USER_APPROVALS_BY_PROVIDER, origin, zoneId);
        getLogger().debug(String.format("Deleted provider approvals '%s'/%s and count:%s", origin, zoneId, approvalCount));
        return approvalCount;
    }

    @Override
    public int deleteByClient(String clientId, String zoneId) {
        int approvalCount = jdbcTemplate.update(DELETE_CLIENT_APPROVALS, clientId, zoneId);
        getLogger().debug(String.format("Deleted client '%s' and %s approvals", clientId, approvalCount));
        return approvalCount;
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        int approvalCount = jdbcTemplate.update(DELETE_USER_APPROVALS, userId, zoneId);
        getLogger().debug(String.format("Deleted user '%s' and %s approvals", userId, approvalCount));
        return approvalCount;
    }

    @Override
    public Log getLogger() {
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

            Approval approval = new Approval()
                .setUserId(userId)
                .setClientId(clientId)
                .setScope(scope)
                .setExpiresAt(expiresAt)
                .setStatus(ApprovalStatus.valueOf(status))
                .setLastUpdatedAt(lastUpdatedAt);
            return approval;
        }
    }
}
