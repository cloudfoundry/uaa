package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.resources.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.getSystemScopes;
import static org.springframework.util.StringUtils.hasText;

public class JdbcScimGroupProvisioning extends AbstractQueryable<ScimGroup>
        implements ScimGroupProvisioning, SystemDeletable {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public Logger getLogger() {
        return logger;
    }

    protected static final String GROUP_FIELDS = "id,displayName,description,created,lastModified,version,identity_zone_id";

    protected static final String GROUP_TABLE = "groups";
    private static final String GROUP_MEMBERSHIP_TABLE = "group_membership";
    private static final String EXTERNAL_GROUP_TABLE = "external_group_mapping";

    final String addGroupSql;
    private final String updateGroupSql;
    private final String getGroupSql;
    private final String getGroupByNameSql;
    private final String queryForFilter;
    private final String deleteGroupSql;
    private final String deleteGroupSqlByIdZoneVersion;
    private final String deleteGroupByZone;
    private final String deleteGroupMembershipByZone;
    private final String deleteExternalGroupByZone;
    private final String deleteZoneAdminMembershipByZone;
    private final String deleteZoneAdminGroupsByZone;
    private final String deleteGroupMembershipByProvider;
    private final String deleteExternalGroupByProvider;
    private final String deleteMemberSql;

    private final JdbcTemplate jdbcTemplate;

    private JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager;
    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;
    private JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;

    public JdbcScimGroupProvisioning(
            final JdbcTemplate jdbcTemplate,
            final JdbcPagingListFactory pagingListFactory,
            final DbUtils dbUtils) throws SQLException {
        super(jdbcTemplate, pagingListFactory, new ScimGroupRowMapper());

        this.jdbcTemplate = jdbcTemplate;

        final String quotedGroupsTableName = dbUtils.getQuotedIdentifier(GROUP_TABLE, jdbcTemplate);
        updateGroupSql = String.format(
                "update %s set version=?, displayName=?, description=?, lastModified=? where id=? and version=? and identity_zone_id=?",
                quotedGroupsTableName
        );
        getGroupSql = String.format(
                "select %s from %s where id=? and identity_zone_id=?",
                GROUP_FIELDS,
                quotedGroupsTableName
        );
        getGroupByNameSql = String.format(
                "select %s from %s where LOWER(displayName)=LOWER(?) and LOWER(identity_zone_id)=LOWER(?)",
                GROUP_FIELDS,
                quotedGroupsTableName
        );
        queryForFilter = String.format(
                "select %s from %s",
                GROUP_FIELDS,
                quotedGroupsTableName
        );
        deleteGroupSql = String.format(
                "delete from %s where id=? and identity_zone_id=?",
                quotedGroupsTableName
        );

        deleteGroupSqlByIdZoneVersion = String.format(
            "delete from %s where id=? and identity_zone_id=? and version=?",
            quotedGroupsTableName
        );

        deleteGroupByZone = String.format(
                "delete from %s where identity_zone_id=?",
                quotedGroupsTableName
        );
        deleteGroupMembershipByZone = String.format(
                "delete from %s where identity_zone_id = ?",
                GROUP_MEMBERSHIP_TABLE
        );
        deleteExternalGroupByZone = String.format(
                "delete from %s where identity_zone_id = ?",
                EXTERNAL_GROUP_TABLE
        );
        deleteZoneAdminMembershipByZone = String.format(
                "delete from %s where group_id in (select id from %s where identity_zone_id=? and displayName like ?)",
                GROUP_MEMBERSHIP_TABLE,
                quotedGroupsTableName
        );
        deleteZoneAdminGroupsByZone = String.format(
                "delete from %s where identity_zone_id=? and displayName like ?",
                quotedGroupsTableName
        );
        deleteGroupMembershipByProvider = String.format(
                "delete from %s where identity_zone_id = ? and origin = ?",
                GROUP_MEMBERSHIP_TABLE
        );
        deleteExternalGroupByProvider = String.format(
                "delete from %s where identity_zone_id = ? and origin = ?",
                EXTERNAL_GROUP_TABLE
        );
        deleteMemberSql = String.format(
                "delete from %s where member_id=? and member_id in (select id from users where id=? and identity_zone_id=?)",
                GROUP_MEMBERSHIP_TABLE
        );
        addGroupSql = String.format(
                "insert into %s ( %s ) values (?,?,?,?,?,?,?)",
                quotedGroupsTableName,
                GROUP_FIELDS
        );
    }

    public void setJdbcScimGroupExternalMembershipManager(final JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager) {
        this.jdbcScimGroupExternalMembershipManager = jdbcScimGroupExternalMembershipManager;
    }

    public void setJdbcScimGroupMembershipManager(final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager) {
        this.jdbcScimGroupMembershipManager = jdbcScimGroupMembershipManager;
    }

    public void setJdbcIdentityZoneProvisioning(JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning) {
        this.jdbcIdentityZoneProvisioning = jdbcIdentityZoneProvisioning;
    }

    void createAndIgnoreDuplicate(final String name, final String zoneId) {
        try {
            create(new ScimGroup(null, name, zoneId), zoneId);
        } catch (ScimResourceAlreadyExistsException ignore) {
            // ignore
        }
    }

    @Override
    public ScimGroup createOrGet(ScimGroup group, String zoneId) {
        try {
            return getByName(group.getDisplayName(), zoneId);
        } catch (IncorrectResultSizeDataAccessException e) {
            createAndIgnoreDuplicate(group.getDisplayName(), zoneId);
            return getByName(group.getDisplayName(), zoneId);
        }
    }

    @Override
    public ScimGroup getByName(String displayName, String zoneId) {
        if (!hasText(displayName)) {
            throw new IncorrectResultSizeDataAccessException("group name must contain text", 1, 0);
        }
        List<ScimGroup> groups = jdbcTemplate.query(getGroupByNameSql, rowMapper, displayName, zoneId);
        if (groups.size() == 1) {
            return groups.get(0);
        } else {
            throw new IncorrectResultSizeDataAccessException("Invalid result size found for:" + displayName, 1, groups.size());
        }
    }

    @Override
    public void onApplicationEvent(AbstractUaaEvent event) {
        if (event instanceof IdentityZoneModifiedEvent zevent && zevent.getEventType() == AuditEventType.IdentityZoneCreatedEvent) {
            final String zoneId = ((IdentityZone) event.getSource()).getId();
            getSystemScopes().forEach(
                    scope -> createAndIgnoreDuplicate(scope, zoneId)
            );
        }
        SystemDeletable.super.onApplicationEvent(event);
    }

    @Override
    protected String getBaseSqlQuery() {
        return queryForFilter;
    }

    @Override
    protected String getTableName() {
        return GROUP_TABLE;
    }


    @Override
    public List<ScimGroup> retrieveAll(final String zoneId) {
        return query("id pr", "created", true, zoneId);
    }

    @Override
    public ScimGroup retrieve(String id, final String zoneId) throws ScimResourceNotFoundException {
        try {
            return jdbcTemplate.queryForObject(getGroupSql, rowMapper, id, zoneId);
        } catch (EmptyResultDataAccessException e) {
            throw new ScimResourceNotFoundException("Group " + id + " does not exist");
        }
    }

    @SuppressWarnings("java:S1874")
    private Set<String> getAllowedUserGroups(String zoneId) {
        Set<String> zoneAllowedGroups = null; // default: all groups allowed
        try {
            IdentityZone currentZone = IdentityZoneHolder.get();
            zoneAllowedGroups = (currentZone.getId().equals(zoneId)) ?
                currentZone.getConfig().getUserConfig().resultingAllowedGroups() :
                jdbcIdentityZoneProvisioning.retrieve(zoneId).getConfig().getUserConfig().resultingAllowedGroups();
        } catch (ZoneDoesNotExistsException e) {
            logger.debug("could not retrieve identity zone with id: {}", zoneId);
        }
        return zoneAllowedGroups;
    }

    @Override
    public ScimGroup create(final ScimGroup group, final String zoneId) throws InvalidScimResourceException {
        validateZoneId(zoneId);
        validateAllowedUserGroups(zoneId, group);
        final String id = UUID.randomUUID().toString();
        logger.debug("creating new group with id: {}", id);
        try {
            validateGroup(group);
            jdbcTemplate.update(addGroupSql, ps -> {
                int pos = 1;
                ps.setString(pos++, id);
                ps.setString(pos++, group.getDisplayName());
                ps.setString(pos++, group.getDescription());
                ps.setTimestamp(pos++, new Timestamp(new Date().getTime()));
                ps.setTimestamp(pos++, new Timestamp(new Date().getTime()));
                ps.setInt(pos++, group.getVersion());
                ps.setString(pos, zoneId);
            });
        } catch (DuplicateKeyException ex) {
            throw new ScimResourceAlreadyExistsException("A group with displayName: " + group.getDisplayName()
                    + " already exists.");
        }
        return retrieve(id, zoneId);
    }

    @Override
    public ScimGroup update(final String id, final ScimGroup group, final String zoneId) throws InvalidScimResourceException,
            ScimResourceNotFoundException {
        validateAllowedUserGroups(zoneId, group);
        try {
            validateZoneId(zoneId);
            validateGroup(group);

            int updated = jdbcTemplate.update(updateGroupSql, ps -> {
                int pos = 1;
                ps.setInt(pos++, group.getVersion() + 1);
                ps.setString(pos++, group.getDisplayName());
                ps.setString(pos++, group.getDescription());
                ps.setTimestamp(pos++, new Timestamp(new Date().getTime()));
                ps.setString(pos++, id);
                ps.setInt(pos++, group.getVersion());
                ps.setString(pos, zoneId);
            });
            if (updated != 1) {
                throw new IncorrectResultSizeDataAccessException(1, updated);
            }
            return retrieve(id, zoneId);
        } catch (DuplicateKeyException ex) {
            throw new InvalidScimResourceException("A group with displayName: " + group.getDisplayName()
                    + " already exists");
        }
    }

    @Override
    public ScimGroup delete(String id, int version, String zoneId) throws ScimResourceNotFoundException {
        validateZoneId(zoneId);
        ScimGroup group = retrieve(id, zoneId);
        jdbcScimGroupMembershipManager.removeMembersByGroupId(id, zoneId);
        jdbcScimGroupExternalMembershipManager.unmapAll(id, zoneId);
        int deleted;
        if (version > 0) {
            deleted = jdbcTemplate.update(deleteGroupSqlByIdZoneVersion, id, zoneId, version);
        } else {
            deleted = jdbcTemplate.update(deleteGroupSql, id, zoneId);
        }
        if (deleted != 1) {
            throw new IncorrectResultSizeDataAccessException(1, deleted);
        }
        return group;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        jdbcTemplate.update(deleteZoneAdminMembershipByZone, IdentityZone.getUaaZoneId(), "zones." + zoneId + ".%");
        jdbcTemplate.update(deleteZoneAdminGroupsByZone, IdentityZone.getUaaZoneId(), "zones." + zoneId + ".%");
        jdbcTemplate.update(deleteExternalGroupByZone, zoneId);
        jdbcTemplate.update(deleteGroupMembershipByZone, zoneId);
        return jdbcTemplate.update(deleteGroupByZone, zoneId);
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        jdbcTemplate.update(deleteExternalGroupByProvider, zoneId, origin);
        return jdbcTemplate.update(deleteGroupMembershipByProvider, zoneId, origin);
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        return jdbcTemplate.update(deleteMemberSql, userId, userId, zoneId);
    }

    private void validateGroup(ScimGroup group) throws ScimResourceConstraintFailedException {
        validateZoneId(group.getZoneId());
    }

    private void validateZoneId(String zoneId) throws ScimResourceConstraintFailedException {
        if (!hasText(zoneId)) {
            throw new ScimResourceConstraintFailedException("zoneId is a required field");
        }
    }

    @Override
    protected void validateOrderBy(String orderBy) throws IllegalArgumentException {
        super.validateOrderBy(orderBy, GROUP_FIELDS);
    }

    private void validateAllowedUserGroups(String zoneId, ScimGroup group) {
        Set<String> allowedGroups = getAllowedUserGroups(zoneId);
        if ((allowedGroups != null) && (!allowedGroups.contains(group.getDisplayName()))) {
            throw new InvalidScimResourceException("The group with displayName: " + group.getDisplayName()
                + " is not allowed in Identity Zone " + zoneId);
        }
    }

}
