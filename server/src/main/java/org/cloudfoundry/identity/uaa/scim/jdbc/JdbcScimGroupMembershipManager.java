package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.apache.commons.lang3.ArrayUtils;
import org.cloudfoundry.identity.uaa.scim.*;
import org.cloudfoundry.identity.uaa.scim.exception.*;
import org.cloudfoundry.identity.uaa.util.TimeBasedExpiringValueMap;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.toSet;
import static org.springframework.util.StringUtils.hasText;

public class JdbcScimGroupMembershipManager implements ScimGroupMembershipManager {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    static final String MEMBERSHIP_FIELDS = "group_id,member_id,member_type,authorities,added,origin";

    static final String MEMBERSHIP_TABLE = "group_membership";

    private static final String ADD_MEMBER_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?,?,?)", MEMBERSHIP_TABLE, MEMBERSHIP_FIELDS + ",identity_zone_id");

    private static final String GET_GROUPS_BY_MEMBER_SQL = String.format("select distinct(group_id) from %s where member_id=? and identity_zone_id=?", MEMBERSHIP_TABLE);

    public static final String DYNAMIC_GET_GROUPS_BY_MEMBER_SQL_BASE = String.format("select %s from %s g, %s gm where gm.group_id = g.id and gm.identity_zone_id = g.identity_zone_id and gm.identity_zone_id = ? and gm.member_id in (",  "g."+ JdbcScimGroupProvisioning.GROUP_FIELDS.replace(",", ",g."), JdbcScimGroupProvisioning.GROUP_TABLE, MEMBERSHIP_TABLE);

    private static final String GET_MEMBERS_SQL = String.format("select %s from %s where group_id=? and identity_zone_id=?", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

    private static final String GET_MEMBER_SQL = String.format("select %s from %s where member_id=? and group_id=? and identity_zone_id=?", MEMBERSHIP_FIELDS, MEMBERSHIP_TABLE);

    private static final String GET_MEMBER_COUNT_SQL = String.format("select count(*) from %s where member_id=? and group_id=? and identity_zone_id=?", MEMBERSHIP_TABLE);

    private static final String DELETE_MEMBER_WITH_ORIGIN_SQL = String.format("delete from %s where member_id=? and origin = ? and identity_zone_id=?", MEMBERSHIP_TABLE);

    private static final String DELETE_MEMBER_SQL = String.format("delete from %s where member_id=? and group_id = ? and identity_zone_id=?", MEMBERSHIP_TABLE);

    private static final String DELETE_MEMBERS_WITH_ORIGIN_GROUP_SQL = String.format("delete from %s where origin=? and identity_zone_id=?", MEMBERSHIP_TABLE);

    private static final String DELETE_MEMBERS_IN_GROUP_SQL = String.format("delete from %s where group_id=? and identity_zone_id=?", MEMBERSHIP_TABLE);

    private static final String DELETE_MEMBER_IN_GROUPS_SQL_USER = String.format("delete from %s where member_id=? and member_type='USER' and identity_zone_id=?", MEMBERSHIP_TABLE);

    private static final String DELETE_MEMBER_IN_GROUPS_SQL_GROUP = String.format("delete from %s where member_id=? and member_type='GROUP' and identity_zone_id=?", MEMBERSHIP_TABLE);

    private static final String GROUP_TABLE = "groups";

    private static final String GET_GROUPS_BY_EXTERNAL_MEMBER_SQL = String.format("select g.id, g.displayName, g.description, g.created, g.lastModified, g.version, g.identity_zone_id" +
                    " from %s m, %s g where m.group_id = g.id and g.identity_zone_id = ? and m.member_id = ? and m.origin = ?",
            MEMBERSHIP_TABLE, GROUP_TABLE);

    @Value("${database.maxParameters:-1}")
    private int maxSqlParameters;

    private final JdbcTemplate jdbcTemplate;
    private final ScimUserProvisioning userProvisioning;
    private final IdentityZoneProvisioning zoneProvisioning;
    private final ScimGroupMemberRowMapper rowMapper;
    private final TimeBasedExpiringValueMap<String, ScimGroup> defaultGroupCache;

    private ScimGroupProvisioning scimGroupProvisioning;

    public JdbcScimGroupMembershipManager(
            final JdbcTemplate jdbcTemplate,
            final TimeService timeService,
            final ScimUserProvisioning userProvisioning,
            final IdentityZoneProvisioning zoneProvisioning) {
        this.jdbcTemplate = jdbcTemplate;
        this.userProvisioning = userProvisioning;
        this.zoneProvisioning = zoneProvisioning;
        rowMapper = new ScimGroupMemberRowMapper();
        defaultGroupCache = new TimeBasedExpiringValueMap<>(timeService);
    }

    public int getMaxSqlParameters() {
        return maxSqlParameters;
    }

    public void setMaxSqlParameters(int maxSqlParameters) {
        this.maxSqlParameters = maxSqlParameters;
    }

    public void setScimGroupProvisioning(final ScimGroupProvisioning groupProvisioning) {
        this.scimGroupProvisioning = groupProvisioning;
    }

    private Set<ScimGroup> getDefaultUserGroups(String zoneId) {
        if (!hasText(zoneId)) {
            return emptySet();
        }
        IdentityZone currentZone = IdentityZoneHolder.get();
        List<String> zoneDefaultGroups = currentZone.getConfig().getUserConfig().getDefaultGroups();
        if (!zoneId.equals(currentZone.getId())) {
            zoneDefaultGroups = zoneProvisioning.retrieve(zoneId).getConfig().getUserConfig().getDefaultGroups();
        }
        return zoneDefaultGroups
                .stream()
                .map(groupName -> createOrGetGroup(groupName, zoneId))
                .collect(toSet());
    }

    ScimGroup createOrGetGroup(String displayName, String zoneId) {
        String key = zoneId + displayName;
        ScimGroup group = defaultGroupCache.get(key);
        if (group == null) {
            group = scimGroupProvisioning.createOrGet(new ScimGroup(null, displayName, zoneId), zoneId);
            defaultGroupCache.put(key, group);
        }
        return group;
    }

    private boolean isDefaultGroup(String groupId, String zoneId) {
        for (ScimGroup g : getDefaultUserGroups(zoneId)) {
            if (g.getId().equals(groupId)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ScimGroupMember addMember(final String groupId, final ScimGroupMember member, final String zoneId)
            throws ScimResourceNotFoundException, MemberAlreadyExistsException {

        if (isDefaultGroup(groupId, zoneId)) {
            throw new MemberAlreadyExistsException("Trying to add member to default group");
        }
        // first validate the supplied groupId, memberId
        validateRequest(groupId, member, zoneId);
        final String type = (member.getType() == null ? ScimGroupMember.Type.USER : member.getType()).toString();
        if (exists(groupId, member.getMemberId(), zoneId)) {
            throw new MemberAlreadyExistsException(member.getMemberId() + " is already part of the group: " + groupId);
        }
        logger.debug("Associating group:" + groupId + " with member:" + member);
        jdbcTemplate.update(ADD_MEMBER_SQL, ps -> {
            ps.setString(1, groupId);
            ps.setString(2, member.getMemberId());
            ps.setString(3, type);
            ps.setNull(4, Types.VARCHAR);
            ps.setTimestamp(5, new Timestamp(new Date().getTime()));
            ps.setString(6, member.getOrigin());
            ps.setString(7, zoneId);
        });
        return getMemberById(groupId, member, ScimGroupMember.Type.valueOf(type));
    }

    @Override
    public List<ScimGroupMember> getMembers(final String groupId, boolean includeEntities, String zoneId) throws ScimResourceNotFoundException {
        List<ScimGroupMember> result = jdbcTemplate.query(
                GET_MEMBERS_SQL,
                rowMapper,
                groupId,
                zoneId
        );

        if (includeEntities) {
            for (ScimGroupMember member : result) {
                if (member.getType().equals(ScimGroupMember.Type.USER)) {
                    ScimUser user = userProvisioning.retrieve(member.getMemberId(), IdentityZoneHolder.get().getId());
                    member.setEntity(user);
                } else if (member.getType().equals(ScimGroupMember.Type.GROUP)) {
                    ScimGroup group = scimGroupProvisioning.retrieve(member.getMemberId(), IdentityZoneHolder.get().getId());
                    member.setEntity(group);
                }
            }
        }

        return new ArrayList<>(result);
    }

    @Override
    public Set<ScimGroup> getGroupsWithMember(final String memberId, boolean transitive, String zoneId)
            throws ScimResourceNotFoundException {
        List<ScimGroup> results = new ArrayList<>();
        getGroupsWithMember(results, Collections.singletonList(memberId), transitive, zoneId);
        if (isUser(memberId)) {
            results.addAll(getDefaultUserGroups(zoneId));
        }
        return new HashSet<>(results);
    }

    private void getGroupsWithMember(List<ScimGroup> results, final List<String> memberId, boolean transitive, final String zoneId) {
        if (results == null) {
            return;
        }
        if (memberId.size() == 0) {
            return;
        }
        if (!IdentityZoneHolder.get().getId().equals(zoneId)) {
            return;
        }
        List<ScimGroup> groups = new ArrayList<>();
        List<String> memberList = new ArrayList<>(memberId);
        try {
        	while (!memberList.isEmpty()) {
        	    int size = maxSqlParameters > 1 ? Math.min(maxSqlParameters - 1, memberList.size()) : memberList.size();
                StringBuilder builder = new StringBuilder(DYNAMIC_GET_GROUPS_BY_MEMBER_SQL_BASE);
                builder.append(memberList.subList(0, size).stream().map(s -> "?").collect(Collectors.joining(", ")));
                builder.append(");");
                Object[] parameterList = ArrayUtils.addAll(new Object[] { zoneId }, memberList.subList(0, size).toArray());
                groups.addAll(jdbcTemplate.query(builder.toString(), new ScimGroupRowMapper(), parameterList));
                memberList = memberList.subList(size, memberList.size());
            }
        } catch (EmptyResultDataAccessException ex) {
            groups = Collections.EMPTY_LIST;
        }

        List<String> nextLevel = new ArrayList<>();
        for (ScimGroup group : groups) {
            if (!results.contains(group)) { // to ensure we don't go into
                // infinite recursion caused by
                // nested group cycles
                results.add(group);
                nextLevel.add(group.getId());
            }
        }
        if (transitive) {
            getGroupsWithMember(results, nextLevel, transitive, zoneId);
        }
    }


    @Override
    public Set<ScimGroup> getGroupsWithExternalMember(final String memberId, final String origin, String zoneId) throws ScimResourceNotFoundException {
        List<ScimGroup> results;

        try {
            results = jdbcTemplate.query(GET_GROUPS_BY_EXTERNAL_MEMBER_SQL, ps -> {
                ps.setString(1, zoneId);
                ps.setString(2, memberId);
                ps.setString(3, origin);
            }, new ScimGroupRowMapper());
        } catch (EmptyResultDataAccessException ex) {
            results = Collections.emptyList();
        }

        return new HashSet<>(results);
    }

    @Override
    public ScimGroupMember getMemberById(String groupId, String memberId, String zoneId) throws ScimResourceNotFoundException,
            MemberNotFoundException {
        try {
            return jdbcTemplate.queryForObject(GET_MEMBER_SQL, rowMapper, memberId, groupId, zoneId);
        } catch (EmptyResultDataAccessException e) {
            throw new MemberNotFoundException("Member " + memberId + " does not exist in group " + groupId);
        }
    }

    private ScimGroupMember getMemberById(String groupId, ScimGroupMember member, ScimGroupMember.Type type) {
        ScimGroupMember sgm = new ScimGroupMember(member.getMemberId(), type);
        sgm.setOrigin(member.getOrigin());
        return sgm;
    }

    private boolean exists(String groupId, String memberId, String zoneId) {
        Integer idResults = jdbcTemplate.queryForObject(GET_MEMBER_COUNT_SQL, Integer.class, memberId, groupId, zoneId);
        return idResults != null && idResults == 1;
    }

    @Override
    public List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members, String zoneId)
            throws ScimResourceNotFoundException {
        List<ScimGroupMember> currentMembers = getMembers(groupId, false, zoneId);
        logger.debug("current-members: " + currentMembers + ", in request: " + members);

        List<ScimGroupMember> currentMembersToRemove = new ArrayList<>(currentMembers);
        currentMembersToRemove.removeAll(members);
        logger.debug("removing members: " + currentMembersToRemove);
        for (ScimGroupMember member : currentMembersToRemove) {
            removeMemberById(groupId, member.getMemberId(), zoneId);
        }

        List<ScimGroupMember> newMembersToAdd = new ArrayList<>(members);
        newMembersToAdd.removeAll(currentMembers);
        logger.debug("adding new members: " + newMembersToAdd);
        for (ScimGroupMember member : newMembersToAdd) {
            addMember(groupId, member, zoneId);
        }

        return getMembers(groupId, false, zoneId);
    }

    @Override
    public ScimGroupMember removeMemberById(final String groupId, final String memberId, final String zoneId)
            throws ScimResourceNotFoundException, MemberNotFoundException {
        ScimGroupMember member = getMemberById(groupId, memberId, zoneId);
        int deleted = jdbcTemplate.update(DELETE_MEMBER_SQL, ps -> {
            ps.setString(2, groupId);
            ps.setString(1, memberId);
            ps.setString(3, zoneId);
        });

        if (deleted != 1) {
            throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", 1, deleted);
        }
        return member;
    }

    @Override
    public List<ScimGroupMember> removeMembersByGroupId(final String groupId, final String zoneId) throws ScimResourceNotFoundException {
        List<ScimGroupMember> members = getMembers(groupId, false, zoneId);
        logger.debug("removing " + members + " members from group: " + groupId);

        int deleted = jdbcTemplate.update(DELETE_MEMBERS_IN_GROUP_SQL, ps -> {
            ps.setString(1, groupId);
            ps.setString(2, zoneId);
        });
        if (deleted != members.size()) {
            throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", members.size(),
                    deleted);
        }

        return members;
    }

    @Override
    public Set<ScimGroup> removeMembersByMemberId(final String memberId, final String zoneId) throws ScimResourceNotFoundException {
        Set<ScimGroup> groups = getGroupsWithMember(memberId, false, zoneId);
        logger.debug("removing " + memberId + " from groups: " + groups);
        int deleted;
        String sql = DELETE_MEMBER_IN_GROUPS_SQL_GROUP;
        if (isUser(memberId)) {
            sql = DELETE_MEMBER_IN_GROUPS_SQL_USER;
        }
        deleted = jdbcTemplate.update(sql, ps -> {
            ps.setString(1, memberId);
            ps.setString(2, zoneId);
        });

        int expectedDelete = isUser(memberId) ? groups.size() - getDefaultUserGroups(zoneId).size() : groups.size();
        if (deleted != expectedDelete) {
            throw new IncorrectResultSizeDataAccessException("unexpected number of members removed", expectedDelete,
                    deleted);
        }

        return groups;
    }

    @Override
    public Set<ScimGroup> removeMembersByMemberId(final String memberId, final String origin, final String zoneId) throws ScimResourceNotFoundException {
        Set<ScimGroup> groups = getGroupsWithMember(memberId, false, zoneId);
        logger.debug("removing " + memberId + " from groups: " + groups);
        int deleted;
        deleted = jdbcTemplate.update(DELETE_MEMBER_WITH_ORIGIN_SQL, ps -> {
            ps.setString(1, memberId);
            ps.setString(2, origin);
            ps.setString(3, zoneId);
        });
        logger.debug(String.format("Deleted %s memberships for member %s", deleted, memberId));
        return groups;
    }

    private boolean isUser(String uuid) {
        try {
            userProvisioning.retrieve(uuid, IdentityZoneHolder.get().getId());
            return true;
        } catch (ScimResourceNotFoundException ex) {
            return false;
        }
    }

    private void validateRequest(String groupId, ScimGroupMember member, String zoneId) {
        if (!hasText(groupId) ||
                !hasText(member.getMemberId()) ||
                !hasText(member.getOrigin())) {
            throw new InvalidScimResourceException("group-id, member-id, origin and member-type must be non-empty");
        }

        if (groupId.equals(member.getMemberId())) { // oops! cycle detected
            throw new InvalidScimResourceException("trying to nest group within itself, aborting");
        }

        // check if the group exists and the member-id is a valid group or user
        // id
        ScimGroup group = scimGroupProvisioning.retrieve(groupId, IdentityZoneHolder.get().getId()); // this will throw a ScimException
        String memberZoneId;
        // if the group does not exist
        // this will throw a ScimException if the group or user does not exist
        if (member.getType() == ScimGroupMember.Type.GROUP) {
            memberZoneId = scimGroupProvisioning.retrieve(member.getMemberId(), IdentityZoneHolder.get().getId()).getZoneId();
        } else {
            memberZoneId = userProvisioning.retrieve(member.getMemberId(), IdentityZoneHolder.get().getId()).getZoneId();
        }
        if (!memberZoneId.equals(group.getZoneId())) {
            throw new ScimResourceConstraintFailedException("The zone of the group and the member must be the same.");
        }
        if (!memberZoneId.equals(zoneId)) {
            throw new ScimResourceConstraintFailedException("Unable to make membership changes in a different zone");
        }
    }

    protected static final class ScimGroupMemberRowMapper implements RowMapper<ScimGroupMember> {
        @Override
        public ScimGroupMember mapRow(ResultSet rs, int rowNum) throws SQLException {
            String memberId = rs.getString(2);
            String memberType = rs.getString(3);
            String origin = rs.getString(6);
            ScimGroupMember sgm = new ScimGroupMember(memberId, ScimGroupMember.Type.valueOf(memberType));
            sgm.setOrigin(origin);
            return sgm;
        }

    }

    @Override
    public void deleteMembersByOrigin(String origin, String zoneId) throws ScimResourceNotFoundException {
        jdbcTemplate.update(DELETE_MEMBERS_WITH_ORIGIN_GROUP_SQL, origin, zoneId);
    }

}
