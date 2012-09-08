package org.cloudfoundry.identity.uaa.scim.groups;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.JdbcPagingList;
import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.*;

public class JdbcScimGroupMembershipManager implements ScimGroupMembershipManager {

    private JdbcTemplate jdbcTemplate;

    private final Log logger = LogFactory.getLog(getClass());

    public static final String MEMBERSHIP_FIELDS = "group_id,member_id,member_type,authorities,added";

    public static final String MEMBERSHIP_TABLE = "group_membership";

    public static final String ADD_MEMBER_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?)", MEMBERSHIP_TABLE, MEMBERSHIP_FIELDS);

    public static final String UPDATE_MEMBER_SQL = String.format("update %s set authorities=? where group_id=? and member_id=?", MEMBERSHIP_TABLE);

    public static final String GET_MEMBERS_SQL = String.format("select %s from %s where group_id=:id", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

    public static final String GET_MEMBER_SQl = String.format("select %s from %s where group_id=? and member_id=?", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

    public static final String DELETE_MEMBER_SQL = String.format("delete from %s where group_id=? and member_id=?", MEMBERSHIP_TABLE);

    public static final String DELETE_MEMBERS_SQL = String.format("delete from %s where group_id=?", MEMBERSHIP_TABLE);

    private final RowMapper<ScimGroupMember> rowMapper = new ScimGroupMemberRowMapper();

    public JdbcScimGroupMembershipManager(JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public ScimGroupMember addMember(final String groupId, final ScimGroupMember member) throws GroupNotFoundException, MemberAlreadyExistsException {
        validateMemberId(member.getId());
        final String authorities = getAuthorities(member);
        final String type = (member.getType() == null ? ScimGroupMember.Type.USER : member.getType()).toString();
        try {
            jdbcTemplate.update(ADD_MEMBER_SQL, new PreparedStatementSetter() {
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, groupId);
                    ps.setString(2, member.getId());
                    ps.setString(3, type);
                    ps.setString(4, authorities);
                    ps.setTimestamp(5, new Timestamp(new Date().getTime()));
                }
            });
        } catch (DuplicateKeyException e) {
            throw new MemberAlreadyExistsException(member.getId() + " is already part of the group: " + groupId);
        }
        return getMemberById(groupId, member.getId());
    }

    @Override
    public List<ScimGroupMember> getMembers(String groupId) throws GroupNotFoundException {
        return new JdbcPagingList<ScimGroupMember>(jdbcTemplate, GET_MEMBERS_SQL, Collections.<String, String> singletonMap("id", groupId), rowMapper, 100);
    }

    @Override
    public List<ScimGroupMember> getAdminMembers(String groupId) throws GroupNotFoundException {
        List<ScimGroupMember> admins = new ArrayList<ScimGroupMember>();
        for (ScimGroupMember m : getMembers(groupId)) {
            if (m.getAuthorities().contains(ScimGroup.Authority.WRITE)) {
                admins.add(m);
            }
        }
        return admins;
    }

    @Override
    public ScimGroupMember getMemberById(String groupId, String memberId) throws GroupNotFoundException, MemberNotFoundException {
        try {
            ScimGroupMember u = jdbcTemplate.queryForObject(GET_MEMBER_SQl, rowMapper, groupId, memberId);
            return u;
        }
        catch (EmptyResultDataAccessException e) {
            throw new MemberNotFoundException("Member " + memberId + " does not exist");
        }
    }

    @Override
    public ScimGroupMember updateMember(final String groupId, final ScimGroupMember member) throws GroupNotFoundException, MemberNotFoundException {

        validateMemberId(member.getId());
        final String authorities = getAuthorities(member);
        int updated = jdbcTemplate.update(UPDATE_MEMBER_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, authorities);
                    ps.setString(2, groupId);
                    ps.setString(3, member.getId());
                }
            });

        if (updated != 1) {
            throw new IncorrectResultSizeDataAccessException("unexpected number of members updated",1, updated);
        }
        return getMemberById(groupId, member.getId());
    }

    @Override
    public List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members) throws GroupNotFoundException {
        List<ScimGroupMember> currentMembers = getMembers(groupId);

        logger.debug("current-members: " + currentMembers + ", in request: " + members);

        List<ScimGroupMember> currentMembersToRemove = new ArrayList<ScimGroupMember>(currentMembers);
        currentMembersToRemove.removeAll(members);
        for (ScimGroupMember member : currentMembersToRemove) {
            removeMemberById(groupId, member.getId());
        }

        List<ScimGroupMember> newMembersToAdd = new ArrayList<ScimGroupMember>(members);
        newMembersToAdd.removeAll(currentMembers);
        for (ScimGroupMember member : newMembersToAdd) {
            addMember(groupId, member);
        }

        List<ScimGroupMember> membersToUpdate = new ArrayList<ScimGroupMember>(members);
        membersToUpdate.retainAll(currentMembers);
        for (ScimGroupMember member : membersToUpdate) {
            updateMember(groupId, member);
        }

        return getMembers(groupId);
    }

    @Override
    public ScimGroupMember removeMemberById(final String groupId, final String memberId) throws GroupNotFoundException, MemberNotFoundException {
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
    public List<ScimGroupMember> removeMembers(final String groupId) throws GroupNotFoundException {
        List<ScimGroupMember> members = getMembers(groupId);
        int deleted = jdbcTemplate.update(DELETE_MEMBERS_SQL, new PreparedStatementSetter() {
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

    private void validateMemberId (String id) {
        if (!StringUtils.hasText(id)) {
            throw new ScimException("specify a valid member-id", HttpStatus.BAD_REQUEST);
        }
        // check if it is an existing group or user id
    }

    private String getAuthorities (ScimGroupMember member) {
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
