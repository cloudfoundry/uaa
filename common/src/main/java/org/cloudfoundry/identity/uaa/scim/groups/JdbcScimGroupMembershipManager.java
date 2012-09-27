package org.cloudfoundry.identity.uaa.scim.groups;

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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.JdbcPagingList;
import org.cloudfoundry.identity.uaa.scim.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SingleColumnRowMapper;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class JdbcScimGroupMembershipManager implements ScimGroupMembershipManager {

	private JdbcTemplate jdbcTemplate;

	private final Log logger = LogFactory.getLog(getClass());

	public static final String MEMBERSHIP_FIELDS = "group_id,member_id,member_type,authorities,added";

	public static final String MEMBERSHIP_TABLE = "group_membership";

	public static final String ADD_MEMBER_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?)", MEMBERSHIP_TABLE, MEMBERSHIP_FIELDS);

	public static final String UPDATE_MEMBER_SQL = String.format("update %s set authorities=? where group_id=? and member_id=?", MEMBERSHIP_TABLE);

	public static final String GET_MEMBERS_SQL = String.format("select %s from %s where group_id=:id", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

	public static final String GET_GROUPS_BY_MEMBER_SQL = String.format("select distinct(group_id) from %s where member_id=?", MEMBERSHIP_TABLE);

	public static final String GET_ADMIN_MEMBERS_SQL = String.format("select %s from %s where group_id=:id and lower(authorities) like '%%write%%'", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

	public static final String GET_MEMBER_SQl = String.format("select %s from %s where group_id=? and member_id=?", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

	public static final String DELETE_MEMBER_SQL = String.format("delete from %s where group_id=? and member_id=?", MEMBERSHIP_TABLE);

	public static final String DELETE_MEMBERS_IN_GROUP_SQL = String.format("delete from %s where group_id=?", MEMBERSHIP_TABLE);

	public static final String DELETE_MEMBER_IN_GROUPS_SQL = String.format("delete from %s where member_id=?", MEMBERSHIP_TABLE);

	private final RowMapper<ScimGroupMember> rowMapper = new ScimGroupMemberRowMapper();

	private ScimUserProvisioning userProvisioning;

	private ScimGroupProvisioning groupProvisioning;

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
	public List<ScimGroupMember> getMembers(String groupId) throws ScimResourceNotFoundException {
		return new JdbcPagingList<ScimGroupMember>(jdbcTemplate, GET_MEMBERS_SQL, Collections.<String, String>singletonMap("id", groupId), rowMapper, 100);
	}

	@Override
	public Set<ScimGroup> getGroupsWithMember(final String memberId, boolean transitive) throws ScimResourceNotFoundException {
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

		List<ScimGroup> results = new ArrayList<ScimGroup>();
		for (String groupId : groupIds) {
			ScimGroup group;
			try {
				group = groupProvisioning.retrieveGroup(groupId);
			} catch (ScimResourceNotFoundException ex) {
				continue;
			}
			results.add(group);
			if (transitive) {
				results.addAll(getGroupsWithMember(groupId, transitive));
			}
		}

		try {
			userProvisioning.retrieveUser(memberId); // this is merely to check that the member is a valid end-user
			results.addAll(groupProvisioning.retrieveGroups("displayName co 'uaa.user'"));
		} catch (ScimResourceNotFoundException e) { } // do nothing if the member if not an end user

		return new HashSet<ScimGroup>(results);
	}

	@Override
	public List<ScimGroupMember> getAdminMembers(String groupId) throws ScimResourceNotFoundException {
		return new JdbcPagingList<ScimGroupMember>(jdbcTemplate, GET_ADMIN_MEMBERS_SQL, Collections.<String, String>singletonMap("id", groupId), rowMapper, 100);
	}

	@Override
	public ScimGroupMember getMemberById(String groupId, String memberId) throws ScimResourceNotFoundException, MemberNotFoundException {
		try {
			ScimGroupMember u = jdbcTemplate.queryForObject(GET_MEMBER_SQl, rowMapper, groupId, memberId);
			return u;
		} catch (EmptyResultDataAccessException e) {
			throw new MemberNotFoundException("Member " + memberId + " does not exist");
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
		if (deleted != groups.size()) {
			throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", groups.size(), deleted);
		}

		return groups;
	}

	private void validateRequest(String groupId, ScimGroupMember member) {
		if (!StringUtils.hasText(groupId) || !StringUtils.hasText(member.getMemberId())) {
			throw new InvalidScimResourceException("group-id, member-id and member-type must be non-empty");
		}

		// check if the group exists and the member-id is a valid group or user id
		groupProvisioning.retrieveGroup(groupId); // this will throw a ScimException if the group does not exist
		// this will throw a ScimException if the group or user does not exist
		if (member.getType() == ScimGroupMember.Type.GROUP) {
			groupProvisioning.retrieveGroup(member.getMemberId());
		} else {
			userProvisioning.retrieveUser(member.getMemberId());
		}
	}

	private String getGroupAuthorities(ScimGroupMember member) {
		if (member.getAuthorities() != null && !member.getAuthorities().isEmpty()) {
			return StringUtils.collectionToCommaDelimitedString(member.getAuthorities());
		} else {
			return StringUtils.collectionToCommaDelimitedString(ScimGroup.GROUP_MEMBER);
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

		private List<ScimGroup.Authority> getAuthorities(String authorities) {
			List<ScimGroup.Authority> result = new ArrayList<ScimGroup.Authority>();
			for (String a : authorities.split(",")) {
				result.add(ScimGroup.Authority.valueOf(a));
			}
			return result;
		}

	}
}
