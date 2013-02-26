package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SingleColumnRowMapper;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class JdbcScimGroupMembershipManager implements ScimGroupMembershipManager {

	private JdbcTemplate jdbcTemplate;

	private final Log logger = LogFactory.getLog(getClass());

	public static final String MEMBERSHIP_FIELDS = "group_id,member_id,member_type,authorities,added";

	public static final String MEMBERSHIP_TABLE = "group_membership";

	public static final String ADD_MEMBER_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?)", MEMBERSHIP_TABLE, MEMBERSHIP_FIELDS);

	public static final String UPDATE_MEMBER_SQL = String.format("update %s set authorities=? where group_id=? and member_id=?", MEMBERSHIP_TABLE);

	public static final String GET_MEMBERS_SQL = String.format("select %s from %s where group_id=?", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

	public static final String GET_GROUPS_BY_MEMBER_SQL = String.format("select distinct(group_id) from %s where member_id=?", MEMBERSHIP_TABLE);

	public static final String GET_MEMBERS_WITH_AUTHORITY_SQL = String.format("select %s from %s where group_id=? and lower(authorities) like ?", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

	public static final String GET_MEMBER_SQl = String.format("select %s from %s where group_id=? and member_id=?", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

	public static final String DELETE_MEMBER_SQL = String.format("delete from %s where group_id=? and member_id=?", MEMBERSHIP_TABLE);

	public static final String DELETE_MEMBERS_IN_GROUP_SQL = String.format("delete from %s where group_id=?", MEMBERSHIP_TABLE);

	public static final String DELETE_MEMBER_IN_GROUPS_SQL = String.format("delete from %s where member_id=?", MEMBERSHIP_TABLE);

	private final RowMapper<ScimGroupMember> rowMapper = new ScimGroupMemberRowMapper();

	private ScimUserProvisioning userProvisioning;

	private ScimGroupProvisioning groupProvisioning;

	private Set<ScimGroup> defaultUserGroups = new HashSet<ScimGroup>();

	public void setDefaultUserGroups(Set<String> groupNames) {
		for (String name : groupNames) {
			List<ScimGroup> g = groupProvisioning.query(String.format("displayName co '%s'", name));
			if (!g.isEmpty()) {
				defaultUserGroups.add(g.get(0));
			} else { // default group must exist, hence if not already present, create it
				defaultUserGroups.add(groupProvisioning.create(new ScimGroup(name)));
			}
		}
	}

	public void setScimUserProvisioning(ScimUserProvisioning userProvisioning) {
		this.userProvisioning = userProvisioning;
	}

	public void setScimGroupProvisioning(ScimGroupProvisioning groupProvisioning) {
		this.groupProvisioning = groupProvisioning;
	}

	public JdbcScimGroupMembershipManager(JdbcTemplate jdbcTemplate) {
		Assert.notNull(jdbcTemplate);
		this.jdbcTemplate = jdbcTemplate;
	}

	@Override
	public ScimGroupMember addMember(final String groupId, final ScimGroupMember member) throws ScimResourceNotFoundException, MemberAlreadyExistsException {
		// first validate the supplied groupId, memberId
		validateRequest(groupId, member);
		final String authorities = getGroupAuthorities(member);
		final String type = (member.getType() == null ? ScimGroupMember.Type.USER : member.getType()).toString();
		try {
			jdbcTemplate.update(ADD_MEMBER_SQL, new PreparedStatementSetter() {
				public void setValues(PreparedStatement ps) throws SQLException {
					ps.setString(1, groupId);
					ps.setString(2, member.getMemberId());
					ps.setString(3, type);
					ps.setString(4, authorities);
					ps.setTimestamp(5, new Timestamp(new Date().getTime()));
				}
			});
		} catch (DuplicateKeyException e) {
			throw new MemberAlreadyExistsException(member.getMemberId() + " is already part of the group: " + groupId);
		}
		return getMemberById(groupId, member.getMemberId());
	}

	@Override
	public List<ScimGroupMember> getMembers(final String groupId) throws ScimResourceNotFoundException {
		return jdbcTemplate.query(GET_MEMBERS_SQL, new PreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, groupId);
			}
		}, rowMapper);
	}

	@Override
	public Set<ScimGroup> getGroupsWithMember(final String memberId, boolean transitive) throws ScimResourceNotFoundException {
		List<ScimGroup> results = new ArrayList<ScimGroup>();
		getGroupsWithMember(results, memberId, transitive);
		if (isUser(memberId)) {
			results.addAll(defaultUserGroups);
		}
		return new HashSet<ScimGroup>(results);
	}

	private void getGroupsWithMember(List<ScimGroup> results, final String memberId, boolean transitive) {
		if (results == null) {
			return;
		}
		List<String> groupIds;
		try {
			groupIds = jdbcTemplate.query(GET_GROUPS_BY_MEMBER_SQL, new PreparedStatementSetter() {
				@Override
				public void setValues(PreparedStatement ps) throws SQLException {
					ps.setString(1, memberId);
				}
			}, new SingleColumnRowMapper<String>(String.class));
		} catch (EmptyResultDataAccessException ex) {
			groupIds = Collections.<String>emptyList();
		}

		for (String groupId : groupIds) {
			ScimGroup group;
			try {
				group = groupProvisioning.retrieve(groupId);
			} catch (ScimResourceNotFoundException ex) {
				continue;
			}
			if (!results.contains(group)) { // to ensure we don't go into infinite recursion caused by nested group cycles
				results.add(group);
				if (transitive) {
					getGroupsWithMember(results, groupId, transitive);
				}
			}
		}

	}

	@Override
	public List<ScimGroupMember> getMembers(final String groupId, final ScimGroupMember.Role permission) throws ScimResourceNotFoundException {
		logger.debug("getting members of type: " + permission + " from group: " + groupId);
		List<ScimGroupMember> members = new ArrayList<ScimGroupMember>();
		members.addAll(jdbcTemplate.query(GET_MEMBERS_WITH_AUTHORITY_SQL, new PreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, groupId);
				ps.setString(2, "%" + permission.toString().toLowerCase() + "%");
			}
		}, rowMapper)
		);
	    return members;
	}

	@Override
	public ScimGroupMember getMemberById(String groupId, String memberId) throws ScimResourceNotFoundException, MemberNotFoundException {
		try {
			ScimGroupMember u = jdbcTemplate.queryForObject(GET_MEMBER_SQl, rowMapper, groupId, memberId);
			return u;
		} catch (EmptyResultDataAccessException e) {
			throw new MemberNotFoundException("Member " + memberId + " does not exist in group " + groupId);
		}
	}

	@Override
	public ScimGroupMember updateMember(final String groupId, final ScimGroupMember member) throws ScimResourceNotFoundException, MemberNotFoundException {
		validateRequest(groupId, member);
		final String authorities = getGroupAuthorities(member);
		int updated = jdbcTemplate.update(UPDATE_MEMBER_SQL, new PreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, authorities);
				ps.setString(2, groupId);
				ps.setString(3, member.getMemberId());
			}
		});

		if (updated != 1) {
			throw new IncorrectResultSizeDataAccessException("unexpected number of members updated", 1, updated);
		}

		return getMemberById(groupId, member.getMemberId());
	}

	@Override
	public List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members) throws ScimResourceNotFoundException {
		List<ScimGroupMember> currentMembers = getMembers(groupId);
		logger.debug("current-members: " + currentMembers + ", in request: " + members);

		List<ScimGroupMember> currentMembersToRemove = new ArrayList<ScimGroupMember>(currentMembers);
		currentMembersToRemove.removeAll(members);
		logger.debug("removing members: " + currentMembersToRemove);
		for (ScimGroupMember member : currentMembersToRemove) {
			removeMemberById(groupId, member.getMemberId());
		}

		List<ScimGroupMember> newMembersToAdd = new ArrayList<ScimGroupMember>(members);
		newMembersToAdd.removeAll(currentMembers);
		logger.debug("adding new members: " + newMembersToAdd);
		for (ScimGroupMember member : newMembersToAdd) {
			addMember(groupId, member);
		}

		List<ScimGroupMember> membersToUpdate = new ArrayList<ScimGroupMember>(members);
		membersToUpdate.retainAll(currentMembers);
		logger.debug("updating members: " + membersToUpdate);
		for (ScimGroupMember member : membersToUpdate) {
			updateMember(groupId, member);
		}

		return getMembers(groupId);
	}

	@Override
	public ScimGroupMember removeMemberById(final String groupId, final String memberId) throws ScimResourceNotFoundException, MemberNotFoundException {
		ScimGroupMember member = getMemberById(groupId, memberId);
		int deleted = jdbcTemplate.update(DELETE_MEMBER_SQL, new PreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, groupId);
				ps.setString(2, memberId);
			}
		});

		if (deleted != 1) {
			throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", 1, deleted);
		}
		return member;
	}

	@Override
	public List<ScimGroupMember> removeMembersByGroupId(final String groupId) throws ScimResourceNotFoundException {
		List<ScimGroupMember> members = getMembers(groupId);
		logger.debug("removing " + members + " members from group: " + groupId);

		int deleted = jdbcTemplate.update(DELETE_MEMBERS_IN_GROUP_SQL, new PreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, groupId);
			}
		});
		if (deleted != members.size()) {
			throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", members.size(), deleted);
		}

		return members;
	}

	@Override
	public Set<ScimGroup> removeMembersByMemberId(final String memberId) throws ScimResourceNotFoundException {
		Set<ScimGroup> groups = getGroupsWithMember(memberId, false);
		logger.debug("removing " + memberId + " from groups: " + groups);

		int deleted = jdbcTemplate.update(DELETE_MEMBER_IN_GROUPS_SQL, new PreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, memberId);
			}
		});
		int expectedDelete = isUser(memberId) ? groups.size() - defaultUserGroups.size() : groups.size();
		if (deleted != expectedDelete) {
			throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", expectedDelete, deleted);
		}

		return groups;
	}

	private boolean isUser(String uuid) {
		try {
			userProvisioning.retrieve(uuid);
			return true;
		} catch (ScimResourceNotFoundException ex) {
			return false;
		}
	}

	private void validateRequest(String groupId, ScimGroupMember member) {
		if (!StringUtils.hasText(groupId) || !StringUtils.hasText(member.getMemberId())) {
			throw new InvalidScimResourceException("group-id, member-id and member-type must be non-empty");
		}

		if(groupId.equals(member.getMemberId())) { // oops! cycle detected
			throw new InvalidScimResourceException("trying to nest group within itself, aborting");
		}

		// check if the group exists and the member-id is a valid group or user id
		groupProvisioning.retrieve(groupId); // this will throw a ScimException if the group does not exist
		// this will throw a ScimException if the group or user does not exist
		if (member.getType() == ScimGroupMember.Type.GROUP) {
			groupProvisioning.retrieve(member.getMemberId());
		} else {
			userProvisioning.retrieve(member.getMemberId());
		}
	}

	private String getGroupAuthorities(ScimGroupMember member) {
		if (member.getRoles() != null && !member.getRoles().isEmpty()) {
			return StringUtils.collectionToCommaDelimitedString(member.getRoles());
		} else {
			return StringUtils.collectionToCommaDelimitedString(ScimGroupMember.GROUP_MEMBER);
		}
	}

	private static final class ScimGroupMemberRowMapper implements RowMapper<ScimGroupMember> {
		@Override
		public ScimGroupMember mapRow(ResultSet rs, int rowNum) throws SQLException {
			String memberId = rs.getString(2);
			String memberType = rs.getString(3);
			String authorities = rs.getString(4);

			return new ScimGroupMember(memberId, ScimGroupMember.Type.valueOf(memberType), getAuthorities(authorities));
		}

		private List<ScimGroupMember.Role> getAuthorities(String authorities) {
			List<ScimGroupMember.Role> result = new ArrayList<ScimGroupMember.Role>();
			for (String a : authorities.split(",")) {
				// for temporary backwards compatibility
				if ("read".equalsIgnoreCase(a)) {
					a = "reader";
				} else if ("write".equalsIgnoreCase(a)) {
					a = "writer";
				}

				result.add(ScimGroupMember.Role.valueOf(a.toUpperCase()));
			}
			return result;
		}

	}
}
