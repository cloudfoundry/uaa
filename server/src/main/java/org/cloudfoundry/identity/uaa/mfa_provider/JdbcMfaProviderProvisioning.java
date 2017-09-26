package org.cloudfoundry.identity.uaa.mfa_provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.springframework.jdbc.core.JdbcTemplate;

public class JdbcMfaProviderProvisioning implements MfaProviderProvisioning, SystemDeletable {

    private static Log logger = LogFactory.getLog(JdbcMfaProviderProvisioning.class);
    public static final String MFA_PROVIDER_FIELDS = "id,name,type,config,active,identity_zone_id,created,lastmodified";
    public static final String CREATE_PROVIDER_SQL = "insert into mfa_providers(" + MFA_PROVIDER_FIELDS + ") values (?,?,?,?,?,?,?,?)";
    protected final JdbcTemplate jdbcTemplate;

    public JdbcMfaProviderProvisioning(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public MfaProvider create(MfaProvider provider, String zoneId) {
        return null;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return 0;
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        return 0;
    }

    @Override
    public int deleteByClient(String clientId, String zoneId) {
        return 0;
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        return 0;
    }

    @Override
    public Log getLogger() {
        return logger;
    }
}
