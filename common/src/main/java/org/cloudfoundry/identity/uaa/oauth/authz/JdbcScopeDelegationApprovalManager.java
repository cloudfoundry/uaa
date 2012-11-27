package org.cloudfoundry.identity.uaa.oauth.authz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcPagingList;
import org.cloudfoundry.identity.uaa.scim.jdbc.ScimSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.jdbc.SearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.jdbc.SearchQueryConverter.ProcessedFilter;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class JdbcScopeDelegationApprovalManager implements ScopeDelegationApprovalManager {

	private JdbcTemplate jdbcTemplate;

	private final Log logger = LogFactory.getLog(getClass());

	private SearchQueryConverter queryConverter = new ScimSearchQueryConverter();

	private final RowMapper<ScopeDelegationApproval> rowMapper = new AuthorizationRowMapper ();

	private static final String TABLE_NAME = "authz_approvals";

	private static final String FIELDS = "userId,clientId,scope,expiresAt";

	private static final String ADD_AUTHZ_SQL = String.format("insert into %s ( %s ) values (?,?,?,?)", TABLE_NAME, FIELDS);

	private static final String REFRESH_AUTHZ_SQL = String.format("update %s set expiresAt=? where userId=? and clientId=? and scope=?", TABLE_NAME);

	private static final String GET_AUTHZ_SQL = String.format("select %s from %s", FIELDS, TABLE_NAME);

	private static final String DELETE_AUTHZ_SQL = String.format("delete from %s", TABLE_NAME);

	private static final String EXPIRE_AUTHZ_SQL = String.format("update %s set expiresAt = :expiry", TABLE_NAME);

	private boolean handleRevocationsAsExpiry = false;

	public JdbcScopeDelegationApprovalManager(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	public void setQueryConverter(SearchQueryConverter queryConverter) {
		this.queryConverter = queryConverter;
	}

	public void setHandleRevocationsAsExpiry(boolean handleRevocationsAsExpiry) {
		this.handleRevocationsAsExpiry = handleRevocationsAsExpiry;
	}

	public boolean refreshApproval(final ScopeDelegationApproval approval) {
		logger.debug(String.format("refreshing approval: [%s]", approval));
		int refreshed = jdbcTemplate.update(REFRESH_AUTHZ_SQL, new PreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setTimestamp(1, new Timestamp(approval.getExpiresAt().getTime()));
				ps.setString(2, approval.getUserId());
				ps.setString(3, approval.getClientId());
				ps.setString(4, approval.getScope());
			}
		});
		if (refreshed != 1) {
			throw new OptimisticLockingFailureException("Attempt to refresh non-existent authorization");
		}
		return true;
	}

	@Override
	public boolean addApproval(final ScopeDelegationApproval approval) {
		logger.debug(String.format("adding approval: [%s]", approval));
		try {
			jdbcTemplate.update(ADD_AUTHZ_SQL, new PreparedStatementSetter() {
				@Override
				public void setValues(PreparedStatement ps) throws SQLException {
					ps.setString(1, approval.getUserId());
					ps.setString(2, approval.getClientId());
					ps.setString(3, approval.getScope());
					ps.setTimestamp(4, new Timestamp(approval.getExpiresAt().getTime()));
				}
			});
		} catch (DuplicateKeyException ex) { // user has already authorized this client for this scope, so just refresh the expiry
			return refreshApproval(approval);
		}
		return true;
	}

	@Override
	public boolean revokeApprovals(String userId, String clientId) {
		return revokeApprovals(String.format("userId eq '%s' and clientId eq '%s'", userId, clientId));
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
			int deleted = jdbcTemplate.update(DELETE_AUTHZ_SQL + " where expiresAt <= ?", new PreparedStatementSetter() {
				@Override
				public void setValues(PreparedStatement ps) throws SQLException {
					ps.setTimestamp(1, new Timestamp(new Date().getTime()));
				}
			});
		} catch (DataAccessException ex) {
			logger.error("Error purging expired approvals", ex);
			return false;
		}
		return true;
	}

	@Override
	public Set<ScopeDelegationApproval> getApprovals(String filter) {
		ProcessedFilter where = queryConverter.convert(filter, null, true);
		logger.debug(String.format("Filtering approvals with filter: [%s]", where));
		try {
			List<ScopeDelegationApproval> approvals = new JdbcPagingList<ScopeDelegationApproval>(jdbcTemplate, GET_AUTHZ_SQL + " where " +
					where.getSql(), where.getParams(), rowMapper, 200);
			return new HashSet<ScopeDelegationApproval>(approvals);
		}
		catch (DataAccessException e) {
			logger.error("Error filtering approvals with filter: " + where, e);
			throw new IllegalArgumentException("Invalid filter: " + filter);
		}
	}

	@Override
	public Set<ScopeDelegationApproval> getApprovals(String userId, String clientId) {
		return getApprovals(String.format("userId eq '%s' and clientId eq '%s'", userId, clientId));
	}

	private static class AuthorizationRowMapper implements RowMapper<ScopeDelegationApproval> {

		@Override
		public ScopeDelegationApproval mapRow(ResultSet rs, int rowNum) throws SQLException {
			String userId = rs.getString(1);
			String clientId = rs.getString(2);
			String scope = rs.getString(3);
			Date expiresAt = rs.getTimestamp(4);

			return new ScopeDelegationApproval(userId, clientId, scope, expiresAt);
		}
	}
}
