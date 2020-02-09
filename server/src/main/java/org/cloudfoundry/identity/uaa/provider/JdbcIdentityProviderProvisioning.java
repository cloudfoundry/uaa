package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component("identityProviderProvisioning")
public class JdbcIdentityProviderProvisioning implements IdentityProviderProvisioning, SystemDeletable {

    private static Logger logger = LoggerFactory.getLogger(JdbcIdentityProviderProvisioning.class);

    public static final String ID_PROVIDER_FIELDS = "id,version,created,lastmodified,name,origin_key,type,config,identity_zone_id,active";

    public static final String CREATE_IDENTITY_PROVIDER_SQL = "insert into identity_provider(" + ID_PROVIDER_FIELDS + ") values (?,?,?,?,?,?,?,?,?,?)";

    public static final String IDENTITY_PROVIDERS_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider where identity_zone_id=?";

    public static final String IDENTITY_ACTIVE_PROVIDERS_QUERY = IDENTITY_PROVIDERS_QUERY + " and active=?";

    public static final String ID_PROVIDER_UPDATE_FIELDS = "version,lastmodified,name,type,config,active".replace(",", "=?,") + "=?";

    public static final String UPDATE_IDENTITY_PROVIDER_SQL = "update identity_provider set " + ID_PROVIDER_UPDATE_FIELDS + " where id=? and identity_zone_id=?";

    public static final String DELETE_IDENTITY_PROVIDER_BY_ORIGIN_SQL = "delete from identity_provider where identity_zone_id=? and origin_key = ?";

    public static final String DELETE_IDENTITY_PROVIDER_BY_ZONE_SQL = "delete from identity_provider where identity_zone_id=?";

    public static final String IDENTITY_PROVIDER_BY_ID_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider " + "where id=? and identity_zone_id=?";

    public static final String IDENTITY_PROVIDER_BY_ORIGIN_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider " + "where origin_key=? and identity_zone_id=? ";

    public static final String IDENTITY_PROVIDER_BY_ORIGIN_QUERY_ACTIVE = IDENTITY_PROVIDER_BY_ORIGIN_QUERY + " and active = ? ";

    protected final JdbcTemplate jdbcTemplate;

    private final RowMapper<IdentityProvider> mapper = new IdentityProviderRowMapper();

    public JdbcIdentityProviderProvisioning(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public IdentityProvider retrieve(String id, String zoneId) {
        return jdbcTemplate.queryForObject(IDENTITY_PROVIDER_BY_ID_QUERY, mapper, id, zoneId);
    }

    @Override
    public List<IdentityProvider> retrieveActive(String zoneId) {
        return jdbcTemplate.query(IDENTITY_ACTIVE_PROVIDERS_QUERY, mapper, zoneId, true);
    }

    @Override
    public List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId) {
        if (activeOnly) {
            return retrieveActive(zoneId);
        } else {
            return jdbcTemplate.query(IDENTITY_PROVIDERS_QUERY, mapper, zoneId);
        }
    }

    @Override
    public IdentityProvider retrieveByOrigin(String origin, String zoneId) {
        return jdbcTemplate.queryForObject(IDENTITY_PROVIDER_BY_ORIGIN_QUERY_ACTIVE, mapper, origin, zoneId, true);
    }

    @Override
    public IdentityProvider retrieveByOriginIgnoreActiveFlag(String origin, String zoneId) {
        return jdbcTemplate.queryForObject(IDENTITY_PROVIDER_BY_ORIGIN_QUERY, mapper, origin, zoneId);
    }

    @Override
    public IdentityProvider create(final IdentityProvider identityProvider, String zoneId) {
        validate(identityProvider);
        final String id = UUID.randomUUID().toString();
        try {
            jdbcTemplate.update(CREATE_IDENTITY_PROVIDER_SQL, ps -> {
                int pos = 1;
                ps.setString(pos++, id);
                ps.setInt(pos++, identityProvider.getVersion());
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                ps.setString(pos++, identityProvider.getName());
                ps.setString(pos++, identityProvider.getOriginKey());
                ps.setString(pos++, identityProvider.getType());
                ps.setString(pos++, JsonUtils.writeValueAsString(identityProvider.getConfig()));
                ps.setString(pos++, zoneId);
                ps.setBoolean(pos, identityProvider.isActive());
            });
        } catch (DuplicateKeyException e) {
            throw new IdpAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }
        return retrieve(id, zoneId);
    }

    @Override
    public IdentityProvider update(final IdentityProvider identityProvider, String zoneId) {
        validate(identityProvider);
        jdbcTemplate.update(UPDATE_IDENTITY_PROVIDER_SQL, ps -> {
            int pos = 1;
            ps.setInt(pos++, identityProvider.getVersion() + 1);
            ps.setTimestamp(pos++, new Timestamp(new Date().getTime()));
            ps.setString(pos++, identityProvider.getName());
            ps.setString(pos++, identityProvider.getType());
            ps.setString(pos++, JsonUtils.writeValueAsString(identityProvider.getConfig()));
            ps.setBoolean(pos++, identityProvider.isActive());
            ps.setString(pos++, identityProvider.getId().trim());
            ps.setString(pos, zoneId);
        });
        return retrieve(identityProvider.getId(), zoneId);
    }

    protected void validate(IdentityProvider provider) {
        if (provider == null) {
            throw new NullPointerException("Provider can not be null.");
        }
        if (!StringUtils.hasText(provider.getIdentityZoneId())) {
            throw new DataIntegrityViolationException("Identity zone ID must be set.");
        }
        //ensure that SAML IDPs have reduntant fields synchronized
        if (OriginKeys.SAML.equals(provider.getType()) && provider.getConfig() != null) {
            SamlIdentityProviderDefinition saml = ObjectUtils.castInstance(provider.getConfig(), SamlIdentityProviderDefinition.class);
            saml.setIdpEntityAlias(provider.getOriginKey());
            saml.setZoneId(provider.getIdentityZoneId());
            provider.setConfig(saml);
        }
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return jdbcTemplate.update(DELETE_IDENTITY_PROVIDER_BY_ZONE_SQL, zoneId);
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        return jdbcTemplate.update(DELETE_IDENTITY_PROVIDER_BY_ORIGIN_SQL, zoneId, origin);
    }

    @Override
    public Logger getLogger() {
        return logger;
    }

    private static final class IdentityProviderRowMapper implements RowMapper<IdentityProvider> {
        @Override
        public IdentityProvider mapRow(ResultSet rs, int rowNum) throws SQLException {
            IdentityProvider identityProvider = new IdentityProvider();
            int pos = 1;
            identityProvider.setId(rs.getString(pos++).trim());
            identityProvider.setVersion(rs.getInt(pos++));
            identityProvider.setCreated(rs.getTimestamp(pos++));
            identityProvider.setLastModified(rs.getTimestamp(pos++));
            identityProvider.setName(rs.getString(pos++));
            identityProvider.setOriginKey(rs.getString(pos++));
            identityProvider.setType(rs.getString(pos++));
            String config = rs.getString(pos++);
            if (StringUtils.hasText(config)) {
                AbstractIdentityProviderDefinition definition;
                switch (identityProvider.getType()) {
                    case OriginKeys.SAML:
                        definition = JsonUtils.readValue(config, SamlIdentityProviderDefinition.class);
                        break;
                    case OriginKeys.OAUTH20:
                        definition = JsonUtils.readValue(config, RawExternalOAuthIdentityProviderDefinition.class);
                        break;
                    case OriginKeys.OIDC10:
                        definition = JsonUtils.readValue(config, OIDCIdentityProviderDefinition.class);
                        break;
                    case OriginKeys.UAA:
                        definition = JsonUtils.readValue(config, UaaIdentityProviderDefinition.class);
                        break;
                    case OriginKeys.LDAP:
                        definition = JsonUtils.readValue(config, LdapIdentityProviderDefinition.class);
                        break;
                    case OriginKeys.KEYSTONE:
                        definition = JsonUtils.readValue(config, KeystoneIdentityProviderDefinition.class);
                        break;
                    default:
                        definition = JsonUtils.readValue(config, AbstractIdentityProviderDefinition.class);
                        break;
                }
                if (definition != null) {
                    identityProvider.setConfig(definition);
                }
            }
            identityProvider.setIdentityZoneId(rs.getString(pos++));
            identityProvider.setActive(rs.getBoolean(pos));
            return identityProvider;
        }
    }
}
