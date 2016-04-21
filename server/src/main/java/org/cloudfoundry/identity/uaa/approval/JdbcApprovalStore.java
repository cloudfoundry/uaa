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

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter.ProcessedFilter;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

public class JdbcApprovalStore implements ApprovalStore, ApplicationEventPublisherAware {

    private final JdbcTemplate jdbcTemplate;

    private JdbcPagingListFactory pagingListFactory;

    private final Log logger = LogFactory.getLog(getClass());

    private final SearchQueryConverter queryConverter;

    private final RowMapper<Approval> rowMapper = new AuthorizationRowMapper();

    private static final String TABLE_NAME = "authz_approvals";

    private static final String FIELDS = "user_id,client_id,scope,expiresAt,status,lastModifiedAt";

    private static final String ADD_AUTHZ_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?,?)", TABLE_NAME,
                    FIELDS);

    private static final String REFRESH_AUTHZ_SQL = String
                    .format("update %s set lastModifiedAt=?, expiresAt=?, status=? where user_id=? and client_Id=? and scope=?",
                                    TABLE_NAME);

    private static final String GET_AUTHZ_SQL = String.format("select %s from %s", FIELDS, TABLE_NAME);

    private static final String DELETE_AUTHZ_SQL = String.format("delete from %s", TABLE_NAME);

    private static final String EXPIRE_AUTHZ_SQL = String.format("update %s set expiresAt = :expiry", TABLE_NAME);

    private boolean handleRevocationsAsExpiry = false;
    private ApplicationEventPublisher applicationEventPublisher;

    public JdbcApprovalStore(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory,
                    SearchQueryConverter queryConverter) {
        Assert.notNull(jdbcTemplate);
        Assert.notNull(queryConverter);
        this.jdbcTemplate = jdbcTemplate;
        this.queryConverter = queryConverter;
        this.pagingListFactory = pagingListFactory;
    }

    public void setHandleRevocationsAsExpiry(boolean handleRevocationsAsExpiry) {
        this.handleRevocationsAsExpiry = handleRevocationsAsExpiry;
    }

    public boolean refreshApproval(final Approval approval) {
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
            }
        });
        if (refreshed != 1) {
            throw new DataIntegrityViolationException("Attempt to refresh non-existent authorization");
        }
        return true;
    }

    @Override
    public boolean addApproval(final Approval approval) {
        logger.debug(String.format("adding approval: [%s]", approval));
        try {
            refreshApproval(approval); // try to refresh the approval
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
                }
            });
            if (count==0) throw new EmptyResultDataAccessException("Approval add failed", 1);
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        publish(new ApprovalModifiedEvent(approval, authentication));
        return true;
    }

    @Override
    public boolean revokeApproval(Approval approval) {
        return revokeApprovals(String.format("user_id eq \"%s\" and client_id eq \"%s\" and scope eq \"%s\"", approval.getUserId(), approval.getClientId(), approval.getScope()));
    }

    @Override
    public boolean revokeApprovals(String filter) {
        ProcessedFilter where = queryConverter.convert(filter, null, true);
        logger.debug(String.format("Filtering approvals with filter: [%s]", where));

        String sql;
        Map<String, Object> sqlParams;
        if (handleRevocationsAsExpiry) {
            // just expire all approvals matching the filter
            sql = EXPIRE_AUTHZ_SQL + " where " + where.getSql();
            sqlParams = where.getParams();
            sqlParams.put("expiry", new Timestamp(new Date().getTime() - 1));
        } else {
            // delete the records
            sql = DELETE_AUTHZ_SQL + " where " + where.getSql();
            sqlParams = where.getParams();
        }

        try {
            int revoked = new NamedParameterJdbcTemplate(jdbcTemplate).update(sql, sqlParams);
            logger.debug(String.format("revoked [%d] approvals matching sql: [%s]", revoked, where));
        } catch (DataAccessException ex) {
            logger.error("Error expiring approvals, possible invalid filter: " + where, ex);
            throw new IllegalArgumentException("Error revoking approvals");
        }
        return true;
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
    public List<Approval> getApprovals(String filter) {
        ProcessedFilter where = queryConverter.convert(filter, null, true);
        logger.debug(String.format("Filtering approvals with filter: [%s]", where));
        try {
            return pagingListFactory.createJdbcPagingList(GET_AUTHZ_SQL + " where " +
                            where.getSql(), where.getParams(), rowMapper, 200);
        } catch (DataAccessException e) {
            logger.error("Error filtering approvals with filter: " + where, e);
            throw new IllegalArgumentException("Invalid filter: " + filter);
        }
    }

    @Override
    public List<Approval> getApprovals(String userId, String clientId) {
        return getApprovals(String.format("user_id eq \"%s\" and client_id eq \"%s\"", userId, clientId));
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

    private static class AuthorizationRowMapper implements RowMapper<Approval> {

        @Override
        public Approval mapRow(ResultSet rs, int rowNum) throws SQLException {
            String userName = rs.getString(1);
            String clientId = rs.getString(2);
            String scope = rs.getString(3);
            Date expiresAt = rs.getTimestamp(4);
            String status = rs.getString(5);
            Date lastUpdatedAt = rs.getTimestamp(6);

            Approval approval = new Approval()
                .setUserId(userName)
                .setClientId(clientId)
                .setScope(scope)
                .setExpiresAt(expiresAt)
                .setStatus(ApprovalStatus.valueOf(status))
                .setLastUpdatedAt(lastUpdatedAt);
            return approval;
        }
    }
}
