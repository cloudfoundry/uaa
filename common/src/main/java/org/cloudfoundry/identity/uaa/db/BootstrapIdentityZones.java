package org.cloudfoundry.identity.uaa.db;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.jdbc.core.JdbcTemplate;

import com.googlecode.flyway.core.api.migration.spring.SpringJdbcMigration;

public class BootstrapIdentityZones implements SpringJdbcMigration {

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        IdentityZone uaa = IdentityZone.getUaa();
        Timestamp t = new Timestamp(uaa.getCreated().getTime());
        jdbcTemplate.update("insert into identity_zone VALUES (?,?,?,?,?,?,?)", uaa.getId(),t,t,uaa.getVersion(),uaa.getSubdomain(),uaa.getName(),uaa.getDescription());
        String tempZoneId = "temp";
        jdbcTemplate.update("insert into identity_zone VALUES (?,?,?,0,'temp','temp','temp')", tempZoneId, t, t);
        String uaaIdpId = UUID.randomUUID().toString();
        jdbcTemplate.update("insert into identity_provider VALUES (?,?,?,0,?,'uaa_internal','uaa','INTERNAL',null)", uaaIdpId, t, t, uaa.getId());
        Map<String,String> originMap = new HashMap<String, String>();
        originMap.put("uaa", uaaIdpId);
        String loginServerIdpId = UUID.randomUUID().toString();
        jdbcTemplate.update("insert into identity_provider VALUES (?,?,?,0,?,'login-server','login-server','INTERNAL',null)", loginServerIdpId, t, t, uaa.getId());
        originMap.put("login-server", loginServerIdpId);
        List<String> origins = jdbcTemplate.queryForList("SELECT DISTINCT origin from users where origin <> 'uaa' and origin <> 'login-server'", String.class);
        for (String origin : origins) {
            String identityProviderId = UUID.randomUUID().toString();  
            originMap.put(origin, identityProviderId);
            jdbcTemplate.update("insert into identity_provider VALUES (?,?,?,0,?,?,?,?,null)",identityProviderId, t, t, tempZoneId,origin,origin,origin);
        }
        jdbcTemplate.update("update oauth_client_details set identity_zone_id = ?",uaa.getId());
        List<String> clientIds = jdbcTemplate.queryForList("SELECT client_id from oauth_client_details", String.class);
        for (String clientId : clientIds) {
            jdbcTemplate.update("insert into client_idp values (?,?) ",clientId,uaaIdpId);
        }
        jdbcTemplate.update("update users set identity_provider_id = (select id from identity_provider where identity_provider.origin_key = users.origin), identity_zone_id = (select identity_zone_id from identity_provider where identity_provider.origin_key = users.origin);");
        jdbcTemplate.update("update group_membership set identity_provider_id = (select id from identity_provider where identity_provider.origin_key = group_membership.origin);");
    }
}
