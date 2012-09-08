package org.cloudfoundry.identity.uaa.scim.groups;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.*;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class JdbcScimGroupProvisioning implements ScimGroupProvisioning {

	private JdbcTemplate jdbcTemplate;

	private SecurityContextAccessor context = new DefaultSecurityContextAccessor();

	private final Log logger = LogFactory.getLog(getClass());

	public static final String GROUP_FIELDS = "id,displayName,created,lastModified,version";

	public static final String GROUP_TABLE = "groups";

	public static final String ADD_GROUP_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?)", GROUP_TABLE, GROUP_FIELDS);

	public static final String UPDATE_GROUP_SQL = String.format("update %s set displayName=?, lastModified=? where id=? and version=?", GROUP_TABLE);

	public static final String GET_GROUPS_SQL = String.format("select %s from %s order by created ASC", GROUP_FIELDS, GROUP_TABLE);

	public static final String GET_GROUP_SQl = String.format("select %s from %s where id=?", GROUP_FIELDS, GROUP_TABLE);

	public static final String GET_GROUP_BY_NAME_SQL = String.format("select %s from %s where displayName=?", GROUP_FIELDS, GROUP_TABLE);

	public static final String DELETE_GROUP_SQL = String.format("delete from %s where id=?", GROUP_TABLE);

	private final RowMapper<ScimGroup> rowMapper = new ScimGroupRowMapper();

	private ScimGroupMembershipManager membershipManager;

	public JdbcScimGroupProvisioning(JdbcTemplate jdbcTemplate) {
		Assert.notNull(jdbcTemplate);
		this.jdbcTemplate = jdbcTemplate;
		membershipManager = new JdbcScimGroupMembershipManager(jdbcTemplate);
	}

	public void setMembershipManager(ScimGroupMembershipManager membershipManager) {
		this.membershipManager = membershipManager;
	}

	public void setContext(SecurityContextAccessor context) {
		this.context = context;
	}

	@Override
	public List<ScimGroup> retrieveGroups(String filter) {
		return retrieveGroups(filter, null, true);
	}

	@Override
	public List<ScimGroup> retrieveGroups(String filter, String sortBy, boolean ascending) {
		throw new UnsupportedOperationException("coming soon");
	}

	@Override
	public List<ScimGroup> retrieveGroups() {
		return new JdbcPagingList<ScimGroup>(jdbcTemplate, GET_GROUPS_SQL, rowMapper, 100);
	}

	@Override
	public ScimGroup retrieveGroup(String id) throws ScimResourceNotFoundException {
		try {
			ScimGroup group = jdbcTemplate.queryForObject(GET_GROUP_SQl, rowMapper, id);
			group.setMembers(membershipManager.getMembers(id));
			return group;
		} catch (EmptyResultDataAccessException e) {
			throw new ScimResourceNotFoundException("Group " + id + " does not exist");
		}
	}

	@Override
	public ScimGroup retrieveGroupByName(String name) throws ScimResourceNotFoundException {
		try {
			ScimGroup group = jdbcTemplate.queryForObject(GET_GROUP_BY_NAME_SQL, rowMapper, name);
			group.setMembers(membershipManager.getMembers(group.getId()));
			return group;
		} catch (EmptyResultDataAccessException e) {
			throw new ScimResourceNotFoundException("Group " + name + " does not exist");
		}
	}

	@Override
	public ScimGroup createGroup(final ScimGroup group) throws InvalidScimResourceException {
		final String id = UUID.randomUUID().toString();
		try {
			jdbcTemplate.update(ADD_GROUP_SQL, new PreparedStatementSetter() {
				@Override
				public void setValues(PreparedStatement ps) throws SQLException {
					ps.setString(1, id);
					ps.setString(2, group.getDisplayName());
					ps.setTimestamp(3, new Timestamp(new Date().getTime()));
					ps.setTimestamp(4, new Timestamp(new Date().getTime()));
					ps.setInt(5, group.getVersion());
				}
			});
		} catch (DuplicateKeyException ex) {
			throw new ScimResourceAlreadyExistsException("A group with displayName: " + group.getDisplayName() + " already exists.");
		}
		if (group.getMembers() != null) {
			for (ScimGroupMember member : group.getMembers()) {
				membershipManager.addMember(id, member);
			}
		}
		return retrieveGroup(id);
	}

	@Override
	public ScimGroup updateGroup(final String id, final ScimGroup group) throws InvalidScimResourceException, ScimResourceNotFoundException {
		checkIfUpdateAllowed(id);
		try {
			int updated = jdbcTemplate.update(UPDATE_GROUP_SQL, new PreparedStatementSetter() {
				@Override
				public void setValues(PreparedStatement ps) throws SQLException {
					ps.setString(1, group.getDisplayName());
					ps.setTimestamp(2, new Timestamp(new Date().getTime()));
					ps.setString(3, id);
					ps.setInt(4, group.getVersion());
				}
			});
			if (updated != 1) {
				throw new IncorrectResultSizeDataAccessException(1, updated);
			}
			if (group.getMembers() != null) {
				membershipManager.updateOrAddMembers(id, group.getMembers());
			}
			return retrieveGroup(id);
		} catch (DuplicateKeyException ex) {
			throw new InvalidScimResourceException("A group with displayName: " + group.getDisplayName() + " already exists");
		}
	}

	@Override
	public ScimGroup removeGroup(String id, int version) throws ScimResourceNotFoundException {
		ScimGroup group = retrieveGroup(id);
		int deleted;
		if (version > 0) {
			deleted = jdbcTemplate.update(DELETE_GROUP_SQL + " and version=?;", id, version);
		} else {
			deleted = jdbcTemplate.update(DELETE_GROUP_SQL, id);
		}
		if (deleted != 1) {
			throw new IncorrectResultSizeDataAccessException(1, deleted);
		}
		if (group.getMembers() != null) {
			membershipManager.removeMembers(id);
		}
		return group;
	}

	protected void checkIfUpdateAllowed(String groupId) {
		if (context.isAdmin()) {
			return;
		}
		if (context.isUser()) {
			if (membershipManager.getAdminMembers(groupId).contains(new ScimGroupMember(context.getUserId()))) {
				return;
			} else
				throw new ScimException(context.getUserId() + " does not have privileges to update group: " + groupId, HttpStatus.UNAUTHORIZED);
		}
		throw new ScimException("Only group members with required privileges can update group", HttpStatus.UNAUTHORIZED);
	}

	private static final class ScimGroupRowMapper implements RowMapper<ScimGroup> {

		@Override
		public ScimGroup mapRow(ResultSet rs, int rowNum) throws SQLException {
			String id = rs.getString(1);
			String name = rs.getString(2);
			Date created = rs.getTimestamp(3);
			Date modified = rs.getTimestamp(4);
			int version = rs.getInt(5);

			ScimGroup group = new ScimGroup(id, name);
			ScimMeta meta = new ScimMeta(created, modified, version);
			group.setMeta(meta);
			return group;
		}
	}
}
