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
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
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

    static final String ADD_GROUP_SQL = String.format(
            "insert into %s ( %s ) values (?,?,?,?,?,?,?)",
            GROUP_TABLE,
            GROUP_FIELDS
    );

    private static final String UPDATE_GROUP_SQL = String.format(
            "update %s set version=?, displayName=?, description=?, lastModified=? where id=? and version=? and identity_zone_id=?",
            GROUP_TABLE
    );

    private static final String GET_GROUP_SQL = String.format(
            "select %s from %s where id=? and identity_zone_id=?",
            GROUP_FIELDS,
            GROUP_TABLE
    );

    private static final String GET_GROUP_BY_NAME_SQL = String.format(
            "select %s from %s where LOWER(displayName)=LOWER(?) and LOWER(identity_zone_id)=LOWER(?)",
            GROUP_FIELDS,
            GROUP_TABLE
    );

    private static final String QUERY_FOR_FILTER = String.format(
            "select %s from %s",
            GROUP_FIELDS,
            GROUP_TABLE
    );

    private static final String DELETE_GROUP_SQL = String.format(
            "delete from %s where id=? and identity_zone_id=?",
            GROUP_TABLE
    );

    private static final String DELETE_GROUP_BY_ZONE = String.format(
            "delete from %s where identity_zone_id=?",
            GROUP_TABLE
    );

    private static final String DELETE_GROUP_MEMBERSHIP_BY_ZONE = String.format(
            "delete from %s where identity_zone_id = ?",
            GROUP_MEMBERSHIP_TABLE
    );

    private static final String DELETE_EXTERNAL_GROUP_BY_ZONE = String.format(
            "delete from %s where identity_zone_id = ?",
            EXTERNAL_GROUP_TABLE
    );

    private static final String DELETE_ZONE_ADMIN_MEMBERSHIP_BY_ZONE = String.format(
            "delete from %s where group_id in (select id from %s where identity_zone_id=? and displayName like ?)",
            GROUP_MEMBERSHIP_TABLE,
            GROUP_TABLE
    );

    private static final String DELETE_ZONE_ADMIN_GROUPS_BY_ZONE = String.format(
            "delete from %s where identity_zone_id=? and displayName like ?",
            GROUP_TABLE
    );

    private static final String DELETE_GROUP_MEMBERSHIP_BY_PROVIDER = String.format(
            "delete from %s where identity_zone_id = ? and origin = ?",
            GROUP_MEMBERSHIP_TABLE
    );

    private static final String DELETE_EXTERNAL_GROUP_BY_PROVIDER = String.format(
            "delete from %s where identity_zone_id = ? and origin = ?",
            EXTERNAL_GROUP_TABLE
    );

    private static final String DELETE_MEMBER_SQL = String.format(
            "delete from %s where member_id=? and member_id in (select id from users where id=? and identity_zone_id=?)",
            GROUP_MEMBERSHIP_TABLE
    );

    private final JdbcTemplate jdbcTemplate;

    private JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager;
    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;

    public JdbcScimGroupProvisioning(
            final JdbcTemplate jdbcTemplate,
            final JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate, pagingListFactory, new ScimGroupRowMapper());

        this.jdbcTemplate = jdbcTemplate;
    }

    public void setJdbcScimGroupExternalMembershipManager(final JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager) {
        this.jdbcScimGroupExternalMembershipManager = jdbcScimGroupExternalMembershipManager;
    }

    public void setJdbcScimGroupMembershipManager(final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager) {
        this.jdbcScimGroupMembershipManager = jdbcScimGroupMembershipManager;
    }

    void createAndIgnoreDuplicate(final String name, final String zoneId) {
        try {
            create(new ScimGroup(null, name, zoneId), zoneId);
        } catch (ScimResourceAlreadyExistsException ignore) {
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
        List<ScimGroup> groups = jdbcTemplate.query(GET_GROUP_BY_NAME_SQL, rowMapper, displayName, zoneId);
        if (groups.size() == 1) {
            return groups.get(0);
        } else {
            throw new IncorrectResultSizeDataAccessException("Invalid result size found for:" + displayName, 1, groups.size());
        }
    }

    @Override
    public void onApplicationEvent(AbstractUaaEvent event) {
        if (event instanceof IdentityZoneModifiedEvent) {
            IdentityZoneModifiedEvent zevent = (IdentityZoneModifiedEvent) event;
            if (zevent.getEventType() == AuditEventType.IdentityZoneCreatedEvent) {
                final String zoneId = ((IdentityZone) event.getSource()).getId();
                getSystemScopes().forEach(
                        scope -> createAndIgnoreDuplicate(scope, zoneId)
                );
            }
        }
        SystemDeletable.super.onApplicationEvent(event);
    }

    @Override
    protected String getBaseSqlQuery() {
        return QUERY_FOR_FILTER;
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
            return jdbcTemplate.queryForObject(GET_GROUP_SQL, rowMapper, id, zoneId);
        } catch (EmptyResultDataAccessException e) {
            throw new ScimResourceNotFoundException("Group " + id + " does not exist");
        }
    }

    @Override
    public ScimGroup create(final ScimGroup group, final String zoneId) throws InvalidScimResourceException {
        final String id = UUID.randomUUID().toString();
        logger.debug("creating new group with id: " + id);
        try {
            validateGroup(group);
            jdbcTemplate.update(ADD_GROUP_SQL, ps -> {
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
        try {
            validateGroup(group);

            int updated = jdbcTemplate.update(UPDATE_GROUP_SQL, ps -> {
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
        ScimGroup group = retrieve(id, zoneId);
        jdbcScimGroupMembershipManager.removeMembersByGroupId(id, zoneId);
        jdbcScimGroupExternalMembershipManager.unmapAll(id, zoneId);
        int deleted;
        if (version > 0) {
            deleted = jdbcTemplate.update(DELETE_GROUP_SQL + " and version=?;", id, zoneId, version);
        } else {
            deleted = jdbcTemplate.update(DELETE_GROUP_SQL, id, zoneId);
        }
        if (deleted != 1) {
            throw new IncorrectResultSizeDataAccessException(1, deleted);
        }
        return group;
    }

    public int deleteByIdentityZone(String zoneId) {
        jdbcTemplate.update(DELETE_ZONE_ADMIN_MEMBERSHIP_BY_ZONE, IdentityZone.getUaaZoneId(), "zones." + zoneId + ".%");
        jdbcTemplate.update(DELETE_ZONE_ADMIN_GROUPS_BY_ZONE, IdentityZone.getUaaZoneId(), "zones." + zoneId + ".%");
        jdbcTemplate.update(DELETE_EXTERNAL_GROUP_BY_ZONE, zoneId);
        jdbcTemplate.update(DELETE_GROUP_MEMBERSHIP_BY_ZONE, zoneId);
        return jdbcTemplate.update(DELETE_GROUP_BY_ZONE, zoneId);
    }

    public int deleteByOrigin(String origin, String zoneId) {
        jdbcTemplate.update(DELETE_EXTERNAL_GROUP_BY_PROVIDER, zoneId, origin);
        return jdbcTemplate.update(DELETE_GROUP_MEMBERSHIP_BY_PROVIDER, zoneId, origin);
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        return jdbcTemplate.update(DELETE_MEMBER_SQL, userId, userId, zoneId);
    }

    private void validateGroup(ScimGroup group) throws ScimResourceConstraintFailedException {
        if (!hasText(group.getZoneId())) {
            throw new ScimResourceConstraintFailedException("zoneId is a required field");
        }
    }

    @Override
    protected void validateOrderBy(String orderBy) throws IllegalArgumentException {
        super.validateOrderBy(orderBy, GROUP_FIELDS);
    }

}
