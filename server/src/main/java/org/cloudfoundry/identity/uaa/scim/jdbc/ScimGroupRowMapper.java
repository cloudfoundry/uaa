package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;

final class ScimGroupRowMapper implements RowMapper<ScimGroup> {

    @Override
    public ScimGroup mapRow(ResultSet rs, int rowNum) throws SQLException {
        int pos = 1;
        String id = rs.getString(pos++);
        String name = rs.getString(pos++);
        String description = rs.getString(pos++);
        Date created = rs.getTimestamp(pos++);
        Date modified = rs.getTimestamp(pos++);
        int version = rs.getInt(pos++);
        String zoneId = rs.getString(pos++);

        ScimGroup group = new ScimGroup(id, name, zoneId);
        group.setDescription(description);

        ScimMeta meta = new ScimMeta(created, modified, version);
        group.setMeta(meta);

        return group;
    }

}
