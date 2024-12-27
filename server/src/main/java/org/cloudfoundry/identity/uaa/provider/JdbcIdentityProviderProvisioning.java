package org.cloudfoundry.identity.uaa.provider;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.slf4j.Logger;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static java.sql.Types.VARCHAR;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.joining;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.isNotEmpty;

@Slf4j
@Component("identityProviderProvisioning")
public class JdbcIdentityProviderProvisioning implements IdentityProviderProvisioning, SystemDeletable {

    public static final String ID_PROVIDER_FIELDS = "id,version,created,lastmodified,name,origin_key,type,config,identity_zone_id,active,alias_id,alias_zid,external_key";

    public static final String CREATE_IDENTITY_PROVIDER_SQL = "insert into identity_provider(" + ID_PROVIDER_FIELDS + ") values (?,?,?,?,?,?,?,?,?,?,?,?,?)";

    public static final String IDENTITY_PROVIDERS_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider where identity_zone_id=?";

    public static final String IDENTITY_ACTIVE_PROVIDERS_QUERY = IDENTITY_PROVIDERS_QUERY + " and active=?";

    public static final String IDENTITY_ACTIVE_PROVIDERS_OF_TYPE_QUERY_TEMPLATE = IDENTITY_ACTIVE_PROVIDERS_QUERY + " and type in (%s)";

    public static final String IDP_WITH_ALIAS_EXISTS_QUERY = "select 1 from identity_provider idp where idp.identity_zone_id = ? and idp.alias_zid <> '' limit 1";

    public static final String ID_PROVIDER_UPDATE_FIELDS = "version,lastmodified,name,type,config,active,alias_id,alias_zid,external_key".replace(",", "=?,") + "=?";

    public static final String UPDATE_IDENTITY_PROVIDER_SQL = "update identity_provider set " + ID_PROVIDER_UPDATE_FIELDS + " where id=? and identity_zone_id=?";

    public static final String DELETE_IDENTITY_PROVIDER_BY_ORIGIN_SQL = "delete from identity_provider where identity_zone_id=? and origin_key = ?";

    public static final String DELETE_IDENTITY_PROVIDER_BY_ZONE_SQL = "delete from identity_provider where identity_zone_id=?";

    public static final String IDENTITY_PROVIDER_BY_ID_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider " + "where id=? and identity_zone_id=?";

    public static final String IDENTITY_PROVIDER_BY_ORIGIN_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider " + "where origin_key=? and identity_zone_id=? ";

    public static final String IDENTITY_PROVIDER_BY_ORIGIN_QUERY_ACTIVE = IDENTITY_PROVIDER_BY_ORIGIN_QUERY + " and active = ? ";

    public static final String IDENTITY_PROVIDER_BY_EXTERNAL_QUERY = IDENTITY_PROVIDERS_QUERY + " and type=? and external_key=?";

    protected final JdbcTemplate jdbcTemplate;

    private final RowMapper<IdentityProvider> mapper = new IdentityProviderRowMapper();

    public JdbcIdentityProviderProvisioning(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public boolean idpWithAliasExistsInZone(final String zoneId) {
        final List<Integer> result = jdbcTemplate.queryForList(
                IDP_WITH_ALIAS_EXISTS_QUERY,
                new Object[]{zoneId},
                new int[]{VARCHAR},
                Integer.class
        );
        // if an IdP with alias is present, the list contains a single element, otherwise it is empty
        return result.size() == 1;
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
    public List<IdentityProvider> retrieveActiveByTypes(final String zoneId, final String... types) {
        if (ObjectUtils.isNotEmpty(types)) {
            // eliminate duplicates
            final Set<String> typesAsSet = new HashSet<>(Arrays.asList(types));

            // adjust the number of SQL parameters in the prepared statement
            final String sqlPlaceholdersForTypes = typesAsSet.stream().map(type -> "?").collect(joining(","));
            final String sql = IDENTITY_ACTIVE_PROVIDERS_OF_TYPE_QUERY_TEMPLATE.formatted(sqlPlaceholdersForTypes);

            final ArrayList<Object> arrayList = new ArrayList<>(typesAsSet.size() + 2);
            arrayList.add(zoneId);
            arrayList.add(true);
            arrayList.addAll(typesAsSet);
            return jdbcTemplate.query(sql, mapper, arrayList.toArray());
        } else {
            return emptyList();
        }
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
    public IdentityProvider retrieveByExternId(String externId, String type, String zoneId) {
        return jdbcTemplate.queryForObject(IDENTITY_PROVIDER_BY_EXTERNAL_QUERY, mapper, zoneId, type, externId);
    }

    @Override
    public IdentityProvider create(final IdentityProvider identityProvider, String zoneId) {
        String externId = validate(identityProvider);
        final String id = UUID.randomUUID().toString();
        try {
            jdbcTemplate.update(CREATE_IDENTITY_PROVIDER_SQL, ps -> {
                int pos = 1;
                ps.setString(pos++, id);
                ps.setInt(pos++, identityProvider.getVersion());
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis())); // created
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis())); // lastmodified
                ps.setString(pos++, identityProvider.getName());
                ps.setString(pos++, identityProvider.getOriginKey());
                ps.setString(pos++, identityProvider.getType());
                ps.setString(pos++, JsonUtils.writeValueAsString(identityProvider.getConfig()));
                ps.setString(pos++, zoneId);
                ps.setBoolean(pos++, identityProvider.isActive());
                ps.setString(pos++, identityProvider.getAliasId());
                ps.setString(pos++, identityProvider.getAliasZid());
                ps.setString(pos, externId);
            });
        } catch (DuplicateKeyException e) {
            throw new IdpAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }
        return retrieve(id, zoneId);
    }

    @Override
    public IdentityProvider update(final IdentityProvider identityProvider, String zoneId) {
        String externId = validate(identityProvider);
        jdbcTemplate.update(UPDATE_IDENTITY_PROVIDER_SQL, ps -> {
            int pos = 1;

            // placeholders in INSERT INTO
            ps.setInt(pos++, identityProvider.getVersion() + 1);
            ps.setTimestamp(pos++, new Timestamp(new Date().getTime())); // lastmodified
            ps.setString(pos++, identityProvider.getName());
            ps.setString(pos++, identityProvider.getType());
            ps.setString(pos++, JsonUtils.writeValueAsString(identityProvider.getConfig()));
            ps.setBoolean(pos++, identityProvider.isActive());
            ps.setString(pos++, identityProvider.getAliasId());
            ps.setString(pos++, identityProvider.getAliasZid());
            ps.setString(pos++, externId);

            // placeholders in WHERE
            ps.setString(pos++, identityProvider.getId().trim());
            ps.setString(pos, zoneId);
        });
        return retrieve(identityProvider.getId(), zoneId);
    }

    private String validate(IdentityProvider provider) {
        if (provider == null) {
            throw new NullPointerException("Provider can not be null.");
        }
        if (!StringUtils.hasText(provider.getIdentityZoneId())) {
            throw new DataIntegrityViolationException("Identity zone ID must be set.");
        }
        String externalKey = null;
        //ensure that SAML IDPs have redundant fields synchronized
        if (OriginKeys.SAML.equals(provider.getType()) && provider.getConfig() != null) {
            SamlIdentityProviderDefinition saml = ObjectUtils.castInstance(provider.getConfig(), SamlIdentityProviderDefinition.class);
            saml.setIdpEntityAlias(provider.getOriginKey());
            saml.setZoneId(provider.getIdentityZoneId());
            provider.setConfig(saml);
            externalKey = saml.getIdpEntityId();
        } else if (provider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition<?> externalOAuthIdentityProviderDefinition) {
            externalKey = externalOAuthIdentityProviderDefinition.getIssuer();
        }
        return externalKey;
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
        return log;
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
            identityProvider.setIdentityZoneId(rs.getString(pos++));
            identityProvider.setActive(rs.getBoolean(pos++));
            identityProvider.setAliasId(rs.getString(pos++));
            identityProvider.setAliasZid(rs.getString(pos++));
            String externalKey = rs.getString(pos);
            if (StringUtils.hasText(config)) {
                AbstractIdentityProviderDefinition definition;
                switch (identityProvider.getType()) {
                    case OriginKeys.SAML:
                        definition = JsonUtils.readValue(config, SamlIdentityProviderDefinition.class);
                        if (isNotEmpty(externalKey)) {
                            Optional.ofNullable(definition).map(SamlIdentityProviderDefinition.class::cast).ifPresent(e -> e.setIdpEntityId(externalKey));
                        }
                        break;
                    case OriginKeys.OAUTH20:
                        definition = JsonUtils.readValue(config, RawExternalOAuthIdentityProviderDefinition.class);
                        if (isNotEmpty(externalKey)) {
                            Optional.ofNullable(definition).map(RawExternalOAuthIdentityProviderDefinition.class::cast).ifPresent(e -> e.setIssuer(externalKey));
                        }
                        break;
                    case OriginKeys.OIDC10:
                        definition = JsonUtils.readValue(config, OIDCIdentityProviderDefinition.class);
                        if (isNotEmpty(externalKey)) {
                            Optional.ofNullable(definition).map(OIDCIdentityProviderDefinition.class::cast).ifPresent(e -> e.setIssuer(externalKey));
                        }
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
            return identityProvider;
        }
    }
}
