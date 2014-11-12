package org.cloudfoundry.identity.uaa.db;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionCallbackWithoutResult;
import org.springframework.transaction.support.TransactionTemplate;

public class MultitenantMigrator implements InitializingBean {
    
    private JdbcTemplate jdbcTemplate;
    private PlatformTransactionManager txManager;

    public void setTxManager(PlatformTransactionManager txManager) {
        this.txManager = txManager;
    }

    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    @Transactional
    public void afterPropertiesSet() throws Exception {
        Integer zoneCount;
        final Timestamp t = new Timestamp(new Date().getTime());
        try {
            zoneCount = jdbcTemplate.queryForObject("select count(id) from identity_zone",Integer.class);
        } catch (Exception e) {
            return;
        }
        if (zoneCount != null && zoneCount == 0) {
            TransactionTemplate tx = new TransactionTemplate(txManager);
            tx.execute(new TransactionCallbackWithoutResult() {
                @Override
                protected void doInTransactionWithoutResult(TransactionStatus status) {
                    String uaaZoneId = UUID.randomUUID().toString();
                    String tempZoneId = UUID.randomUUID().toString();
                    jdbcTemplate.update("insert into identity_zone VALUES (?,?,?,0,'uaa',null,'id-zone','The system zone')", uaaZoneId, t, t);
                    jdbcTemplate.update("insert into identity_zone VALUES (?,?,?,0,'temp','temp','temp','temp')", tempZoneId, t, t);
                    String uaaIdpId = UUID.randomUUID().toString();
                    jdbcTemplate.update("insert into identity_provider VALUES (?,?,?,0,?,'uaa_internal','uaa','INTERNAL',null)", uaaIdpId, t, t, uaaZoneId);
                    Map<String,String> originMap = new HashMap<String, String>();
                    originMap.put("uaa", uaaIdpId);
                    List<String> origins = jdbcTemplate.queryForList("SELECT DISTINCT origin from users where origin <> 'uaa'", String.class);
                    for (String origin : origins) {
                        String identityProviderId = UUID.randomUUID().toString();  
                        originMap.put(origin, identityProviderId);
                        jdbcTemplate.update("insert into identity_provider VALUES (?,?,?,0,?,?,?,?,null)",identityProviderId, t, t, tempZoneId,origin,origin,origin);
                    }
                    jdbcTemplate.update("update oauth_client_details set identity_zone_id = ?",uaaZoneId);
                    List<String> clientIds = jdbcTemplate.queryForList("SELECT client_id from oauth_client_details", String.class);
                    for (String clientId : clientIds) {
                        jdbcTemplate.update("insert into client_idp values (?,?) ",clientId,uaaIdpId);
                    }
                    jdbcTemplate.update("update users set identity_provider_id = (select id from identity_provider where identity_provider.origin_key = users.origin);");
                    jdbcTemplate.update("update group_membership set identity_provider_id = (select id from identity_provider where identity_provider.origin_key = group_membership.origin);");
                }
            });
            
        }
    }
}
