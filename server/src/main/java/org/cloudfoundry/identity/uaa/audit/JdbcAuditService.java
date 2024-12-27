/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.audit;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;


public class JdbcAuditService implements UaaAuditService {

    private final JdbcTemplate template;

    public JdbcAuditService(JdbcTemplate template) {
        this.template = template;
    }

    protected JdbcTemplate getJdbcTemplate() {
        return template;
    }

    @Override
    public List<AuditEvent> find(String principalId, long after, String zoneId) {
        return template.query("select event_type, principal_id, origin, event_data, created, identity_zone_id from sec_audit where " +
                "principal_id=? and identity_zone_id=? and created > ? order by created desc", new AuditEventRowMapper(), principalId
        , zoneId, new Timestamp(after));
    }

    @Override
    public void log(AuditEvent auditEvent, String zoneId) {
        String origin = auditEvent.getOrigin();
        String data = auditEvent.getData();
        origin = origin == null ? "" : origin;
        origin = origin.length() > 255 ? origin.substring(0, 255) : origin;
        data = data == null ? "" : data;
        data = data.length() > 255 ? data.substring(0, 255) : data;
        template.update("insert into sec_audit (principal_id, event_type, origin, event_data, identity_zone_id) values (?,?,?,?,?)",
                auditEvent.getPrincipalId(), auditEvent.getType().getCode(), origin,
                data, zoneId);
    }

    private class AuditEventRowMapper implements RowMapper<AuditEvent> {
        @Override
        public AuditEvent mapRow(ResultSet rs, int rowNum) throws SQLException {
            AuditEventType eventType = AuditEventType.fromCode(rs.getInt(1));
            String principalId = nullSafeTrim(rs.getString(2));
            String origin = nullSafeTrim(rs.getString(3));
            String data = nullSafeTrim(rs.getString(4));
            long time = rs.getTimestamp(5).getTime();
            String identityZoneId = nullSafeTrim(rs.getString(6));
            return new AuditEvent(eventType, principalId, origin,
                    data, time, identityZoneId, null, null);
        }
    }

    private static String nullSafeTrim(String s) {
        return s == null ? null : s.trim();
    }
}
