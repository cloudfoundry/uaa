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
package org.cloudfoundry.identity.uaa.scim.jdbc;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SingleColumnRowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class JdbcScimGroupMembershipManager extends AbstractQueryable<ScimGroupMember> implements ScimGroupMembershipManager {

    private JdbcTemplate jdbcTemplate;

    private final Log logger = LogFactory.getLog(getClass());

    public static final String MEMBERSHIP_FIELDS = "group_id,member_id,member_type,authorities,added,origin";

    public static final String MEMBERSHIP_TABLE = "group_membership";

    public static final String ADD_MEMBER_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?,?)", MEMBERSHIP_TABLE, MEMBERSHIP_FIELDS);

    public static final String UPDATE_MEMBER_SQL = String.format("update %s set authorities=? where group_id=? and member_id=?", MEMBERSHIP_TABLE);

    public static final String GET_MEMBERS_FILTER_SQL = String.format("select %s from %s where group_id in (select id from groups where identity_zone_id=%s)", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE, "'%s'");

    public static final String GET_GROUPS_BY_MEMBER_SQL = String.format("select distinct(group_id) from %s where member_id=? and group_id in (select id from groups where identity_zone_id=?)", MEMBERSHIP_TABLE);

    public static final String GET_MEMBERS_WITH_AUTHORITY_SQL = String.format("select %s from %s where group_id=? and lower(authorities) like ?", MEMBERSHIP_FIELDS,MEMBERSHIP_TABLE);

    public static final String GET_MEMBER_SQL = String.format("select %s from %s where member_id=? and group_id in (select id from groups where id=? and identity_zone_id=?)",MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

    public static final String DELETE_MEMBER_SQL = String.format("delete from %s where member_id=? and group_id in (select id from groups where id=? and identity_zone_id=?)",MEMBERSHIP_TABLE);

    public static final String DELETE_MEMBERS_IN_GROUP_SQL = String.format("delete from %s where group_id in (select id from groups where id=? and identity_zone_id=?)",MEMBERSHIP_TABLE);

    public static final String DELETE_MEMBER_IN_GROUPS_SQL_USER = String.format("delete from %s where member_id in (select id from users where id=? and identity_zone_id=?)",MEMBERSHIP_TABLE);

    public static final String DELETE_MEMBER_IN_GROUPS_SQL_GROUP = String.format("delete from %s where member_id in (select id from groups where id=? and identity_zone_id=?)",MEMBERSHIP_TABLE);

    private ScimUserProvisioning userProvisioning;

    private ScimGroupProvisioning groupProvisioning;

    private Map<IdentityZone,Set<ScimGroup>> defaultUserGroups = new ConcurrentHashMap<>();

    //we do not yet support default user groups for other zones
    public void setDefaultUserGroups(Set<String> groupNames) {
        Set<ScimGroup> usergroups = new HashSet<>();
        for (String name : groupNames) {
            List<ScimGroup> g = groupProvisioning.query(String.format("displayName co \"%s\" and identity_zone_id eq \""+IdentityZone.getUaa().getId()+"\"", name));
            if (!g.isEmpty()) {
                usergroups.add(g.get(0));
            } else { // default group must exist, hence if not already present,
                // create it
                usergroups.add(groupProvisioning.create(new ScimGroup(null, name, IdentityZone.getUaa().getId())));
            }
        }
        defaultUserGroups.put(IdentityZone.getUaa(), usergroups);
    }

    public Set<ScimGroup> getDefaultUserGroups(IdentityZone zone) {
        Set<ScimGroup> groups = defaultUserGroups.get(zone);
        if (groups==null) {
            return Collections.EMPTY_SET;
        }
        return groups;
    }

    public void setScimUserProvisioning(ScimUserProvisioning userProvisioning) {
        this.userProvisioning = userProvisioning;
    }

    public void setScimGroupProvisioning(ScimGroupProvisioning groupProvisioning) {
        this.groupProvisioning = groupProvisioning;
    }

    public JdbcScimGroupMembershipManager(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate,pagingListFactory,new ScimGroupMemberRowMapper());
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    protected String getBaseSqlQuery() {
        return String.format(GET_MEMBERS_FILTER_SQL, IdentityZoneHolder.get().getId());
    }

    @Override
    protected String getTableName() {
        return MEMBERSHIP_TABLE;
    }

    @Override
    public int delete(String filter) {
        SearchQueryConverter.ProcessedFilter where = getQueryConverter().convert(filter, null, false);
        logger.debug("Filtering groups with SQL: " + where);
        try {
            String completeSql = "DELETE FROM "+getTableName() + " WHERE group_id IN (SELECT id FROM groups WHERE identity_zone_id='"+IdentityZoneHolder.get().getId()+"') AND  " + where.getSql();
            logger.debug("delete sql: " + completeSql + ", params: " + where.getParams());
            return new NamedParameterJdbcTemplate(jdbcTemplate).update(completeSql, where.getParams());
        } catch (DataAccessException e) {
            logger.debug("Filter '" + filter + "' generated invalid SQL", e);
            throw new IllegalArgumentException("Invalid delete filter: " + filter);
        }
    }

    @Override
    protected String getQuerySQL(String filter, SearchQueryConverter.ProcessedFilter where) {
        boolean containsWhereClause = getBaseSqlQuery().contains(" where ");
        return filter == null || filter.trim().length()==0 ?
            getBaseSqlQuery() :
            getBaseSqlQuery() + (containsWhereClause ? " and " : " where ") + where.getSql();
    }

    public boolean isDefaultGroup(String groupId) {
        for (ScimGroup g : getDefaultUserGroups(IdentityZoneHolder.get())) {
            if (g.getId().equals(groupId)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ScimGroupMember addMember(final String groupId, final ScimGroupMember member)
                    throws ScimResourceNotFoundException, MemberAlreadyExistsException {

        if (isDefaultGroup(groupId)) {
            throw new MemberAlreadyExistsException("Trying to add member to default group");
        }
        // first validate the supplied groupId, memberId
        validateRequest(groupId, member);
        final String authorities = getGroupAuthorities(member);
        final String type = (member.getType() == null ? ScimGroupMember.Type.USER : member.getType()).toString();
        try {
            logger.debug("Associating group:"+groupId+" with member:"+member);
            jdbcTemplate.update(ADD_MEMBER_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, groupId);
                    ps.setString(2, member.getMemberId());
                    ps.setString(3, type);
                    ps.setString(4, authorities);
                    ps.setTimestamp(5, new Timestamp(new Date().getTime()));
                    ps.setString(6, member.getOrigin());
                }
            });
        } catch (DuplicateKeyException e) {
            throw new MemberAlreadyExistsException(member.getMemberId() + " is already part of the group: " + groupId);
        }
        return getMemberById(groupId, member.getMemberId());
    }

    @Override
    public List<ScimGroupMember> getMembers(final String groupId, String filter, boolean includeEntities) throws ScimResourceNotFoundException {
        String scopedFilter;
        if (StringUtils.hasText(filter)) {
            // validate filter syntax
            getQueryConverter().convert(filter, "member_id", true);
            scopedFilter = String.format("group_id eq \"%s\" and (%s)", groupId, filter);
        }
        else {
            scopedFilter = String.format("group_id eq \"%s\"", groupId);
        }
        List<ScimGroupMember> result = query(scopedFilter, "member_id", true);

        if(includeEntities) {
            for(ScimGroupMember member : result) {
                if(member.getType().equals(ScimGroupMember.Type.USER)) {
                    ScimUser user = userProvisioning.retrieve(member.getMemberId());
                    member.setEntity(user);
                } else if(member.getType().equals(ScimGroupMember.Type.GROUP)) {
                    ScimGroup group = groupProvisioning.retrieve(member.getMemberId());
                    member.setEntity(group);
                }
            }
        }

        return new ArrayList<>(result);
    }

    @Override
    public Set<ScimGroup> getGroupsWithMember(final String memberId, boolean transitive)
                    throws ScimResourceNotFoundException {
        List<ScimGroup> results = new ArrayList<>();
        getGroupsWithMember(results, memberId, transitive);
        if (isUser(memberId)) {
            results.addAll(getDefaultUserGroups(IdentityZoneHolder.get()));
        }
        return new HashSet<>(results);
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
                    ps.setString(2, IdentityZoneHolder.get().getId());
                }
            }, new SingleColumnRowMapper<>(String.class));
        } catch (EmptyResultDataAccessException ex) {
            groupIds = Collections.EMPTY_LIST;
        }

        for (String groupId : groupIds) {
            ScimGroup group;
            try {
                group = groupProvisioning.retrieve(groupId);
            } catch (ScimResourceNotFoundException ex) {
                continue;
            }
            if (!results.contains(group)) { // to ensure we don't go into
                                            // infinite recursion caused by
                                            // nested group cycles
                results.add(group);
                if (transitive) {
                    getGroupsWithMember(results, groupId, transitive);
                }
            }
        }

    }

    @Override
    public List<ScimGroupMember> getMembers(final String groupId, final ScimGroupMember.Role permission)
                    throws ScimResourceNotFoundException {
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
    public ScimGroupMember getMemberById(String groupId, String memberId) throws ScimResourceNotFoundException,
                    MemberNotFoundException {
        try {
            ScimGroupMember u = jdbcTemplate.queryForObject(GET_MEMBER_SQL, rowMapper, memberId, groupId, IdentityZoneHolder.get().getId());
            return u;
        } catch (EmptyResultDataAccessException e) {
                throw new MemberNotFoundException("Member " + memberId + " does not exist in group " + groupId);
        }
    }

    @Override
    public ScimGroupMember updateMember(final String groupId, final ScimGroupMember member)
                    throws ScimResourceNotFoundException, MemberNotFoundException {
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

        if(updated == 0) {
            throw new MemberNotFoundException("Member " + member.getMemberId() + " does not exist in group " + groupId);
        }

        if (updated != 1) {
            throw new IncorrectResultSizeDataAccessException("unexpected number of members updated", 1, updated);
        }

        return getMemberById(groupId, member.getMemberId());
    }

    @Override
    public List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members)
                    throws ScimResourceNotFoundException {
        List<ScimGroupMember> currentMembers = getMembers(groupId, null, false);
        logger.debug("current-members: " + currentMembers + ", in request: " + members);

        List<ScimGroupMember> currentMembersToRemove = new ArrayList<>(currentMembers);
        currentMembersToRemove.removeAll(members);
        logger.debug("removing members: " + currentMembersToRemove);
        for (ScimGroupMember member : currentMembersToRemove) {
            removeMemberById(groupId, member.getMemberId());
        }

        List<ScimGroupMember> newMembersToAdd = new ArrayList<>(members);
        newMembersToAdd.removeAll(currentMembers);
        logger.debug("adding new members: " + newMembersToAdd);
        for (ScimGroupMember member : newMembersToAdd) {
            addMember(groupId, member);
        }

        List<ScimGroupMember> membersToUpdate = new ArrayList<>(members);
        membersToUpdate.retainAll(currentMembers);
        logger.debug("updating members: " + membersToUpdate);
        for (ScimGroupMember member : membersToUpdate) {
            updateMember(groupId, member);
        }

        return getMembers(groupId, null, false);
    }

    @Override
    public ScimGroupMember removeMemberById(final String groupId, final String memberId)
                    throws ScimResourceNotFoundException, MemberNotFoundException {
        ScimGroupMember member = getMemberById(groupId, memberId);
        int deleted = jdbcTemplate.update(DELETE_MEMBER_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(2, groupId);
                ps.setString(1, memberId);
                ps.setString(3, IdentityZoneHolder.get().getId());
            }
        });

        if (deleted != 1) {
            throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", 1, deleted);
        }
        return member;
    }

    @Override
    public List<ScimGroupMember> removeMembersByGroupId(final String groupId) throws ScimResourceNotFoundException {
        List<ScimGroupMember> members = getMembers(groupId, null, false);
        logger.debug("removing " + members + " members from group: " + groupId);

        int deleted = jdbcTemplate.update(DELETE_MEMBERS_IN_GROUP_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
            ps.setString(1, groupId);
            ps.setString(2, IdentityZoneHolder.get().getId());
            }
        });
        if (deleted != members.size()) {
            throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", members.size(),
                            deleted);
        }

        return members;
    }

    @Override
    public Set<ScimGroup> removeMembersByMemberId(final String memberId) throws ScimResourceNotFoundException {
        Set<ScimGroup> groups = getGroupsWithMember(memberId, false);
        logger.debug("removing " + memberId + " from groups: " + groups);
        int deleted = 0;
        String sql = DELETE_MEMBER_IN_GROUPS_SQL_GROUP;
        if (isUser(memberId)) {
               sql = DELETE_MEMBER_IN_GROUPS_SQL_USER;
        }
        deleted = jdbcTemplate.update(sql, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
            ps.setString(1, memberId);
            ps.setString(2, IdentityZoneHolder.get().getId());
            }
        });

        int expectedDelete = isUser(memberId) ? groups.size() - getDefaultUserGroups(IdentityZoneHolder.get()).size() : groups.size();
        if (deleted != expectedDelete) {
            throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", expectedDelete,
                            deleted);
        }

        return groups;
    }

    @Override
    protected void validateOrderBy(String orderBy) throws IllegalArgumentException {
        super.validateOrderBy(orderBy, MEMBERSHIP_FIELDS);
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
        if (!StringUtils.hasText(groupId) ||
            !StringUtils.hasText(member.getMemberId()) ||
            !StringUtils.hasText(member.getOrigin())) {
            throw new InvalidScimResourceException("group-id, member-id, origin and member-type must be non-empty");
        }

        if (groupId.equals(member.getMemberId())) { // oops! cycle detected
            throw new InvalidScimResourceException("trying to nest group within itself, aborting");
        }

        // check if the group exists and the member-id is a valid group or user
        // id
        ScimGroup group = groupProvisioning.retrieve(groupId); // this will throw a ScimException
        String memberZoneId;
                                             // if the group does not exist
        // this will throw a ScimException if the group or user does not exist
        if (member.getType() == ScimGroupMember.Type.GROUP) {
            memberZoneId = groupProvisioning.retrieve(member.getMemberId()).getZoneId();
        } else {
            memberZoneId = userProvisioning.retrieve(member.getMemberId()).getZoneId();
        }
        if (!memberZoneId.equals(group.getZoneId())) {
            throw new ScimResourceConstraintFailedException("The zone of the group and the member must be the same.");
        }
        if (!memberZoneId.equals(IdentityZoneHolder.get().getId())) {
            throw new ScimResourceConstraintFailedException("Unable to make membership changes in a different zone");
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
            Date added = rs.getDate(5);
            String origin = rs.getString(6);
            ScimGroupMember sgm = new ScimGroupMember(memberId, ScimGroupMember.Type.valueOf(memberType), getAuthorities(authorities));
            sgm.setOrigin(origin);
            return sgm;
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
