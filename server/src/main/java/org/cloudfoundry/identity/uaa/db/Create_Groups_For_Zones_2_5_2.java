/*
 * ******************************************************************************
 *  *     Cloud Foundry
 *  *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *  *
 *  *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  *     You may not use this product except in compliance with the License.
 *  *
 *  *     This product includes a number of subcomponents with
 *  *     separate copyright notices and license terms. Your use of these
 *  *     subcomponents is subject to the terms and conditions of the
 *  *     subcomponent's license, as noted in the LICENSE file.
 *  ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class Create_Groups_For_Zones_2_5_2 implements SpringJdbcMigration {

    private static Logger logger = LoggerFactory.getLogger(Create_Groups_For_Zones_2_5_2.class);

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) {
        String groupCreateSQL = "INSERT INTO groups (id,displayName,created,lastModified,version,identity_zone_id) VALUES (?,?,?,?,?,?)";
        Map<String, Map<String, String>> zoneIdToGroupNameToGroupId = new HashMap<>();

        //duplicate all existing groups across zones
        List<String> zones = jdbcTemplate.queryForList("SELECT id FROM identity_zone WHERE id <> 'uaa'", String.class);
        List<String> groups = jdbcTemplate.queryForList("SELECT displayName FROM groups WHERE identity_zone_id = 'uaa'", String.class);
        for (String zoneId : zones) {
            Map<String, String> groupNameToGroupId = new HashMap<>();
            zoneIdToGroupNameToGroupId.put(zoneId, groupNameToGroupId);
            Timestamp now = new Timestamp(System.currentTimeMillis());
            for (String displayName : groups) {
                if (displayName.startsWith("zones.")) {
                    continue;
                }
                String id = UUID.randomUUID().toString();
                jdbcTemplate.update(
                    groupCreateSQL,
                    id,
                    displayName,
                    now,
                    now,
                    0,
                    zoneId);
                groupNameToGroupId.put(displayName, id);
            }
        }
        //convert all user memberships from other zones
        String userSQL = "SELECT gm.group_id, gm.member_id, g.displayName, u.identity_zone_id FROM group_membership gm, groups g, users u WHERE gm.member_type='USER' AND gm.member_id = u.id AND gm.group_id = g.id AND u.identity_zone_id <> 'uaa'";
        List<Map<String,Object>> userMembers = jdbcTemplate.queryForList(userSQL);
        for (Map<String, Object> userRow : userMembers) {
            String zoneId = (String) userRow.get("identity_zone_id");
            String displayName = (String) userRow.get("displayName");
            String memberId = (String)userRow.get("member_id");
            String oldGroupId = (String)userRow.get("group_id");
            Map<String, String> groupNameToGroupId = zoneIdToGroupNameToGroupId.get(zoneId);
            if (groupNameToGroupId==null) {
                //this zone doesnt exist anymore. delete the row
                int count = jdbcTemplate.update("DELETE FROM group_membership WHERE group_id=? AND member_id=?", oldGroupId, memberId);
                if (count!=1) {
                    logger.error("Unable to delete membership for non existent zone(group:"+oldGroupId+", member:"+memberId+")");
                }
            } else {
                String groupId = groupNameToGroupId.get(displayName);
                if (StringUtils.hasText(groupId)) {
                    int count = jdbcTemplate.update("UPDATE group_membership SET group_id=? WHERE group_id=? AND member_id=?", groupId, oldGroupId, memberId);
                    if (count != 1) {
                        logger.error("Unable to update group membership for migrated zone(old group:" + oldGroupId + ", member:" + memberId + ", new group:" + groupId + ")");
                    }
                } else {
                    logger.error("Will not migrate (old group:" + oldGroupId + ", member:" + memberId + ", new group:" + groupId + "). Incorrectly mapped zones group? ("+displayName+")");
                }
            }
        }
        userMembers.clear();
     }
}
