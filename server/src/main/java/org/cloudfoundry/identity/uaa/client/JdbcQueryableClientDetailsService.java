package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.resources.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

@Component("clientDetailsService")
public class JdbcQueryableClientDetailsService
        extends AbstractQueryable<ClientDetails>
        implements QueryableResourceManager<ClientDetails> {

    private static final Logger logger = LoggerFactory.getLogger(JdbcQueryableClientDetailsService.class);

    private final MultitenantJdbcClientDetailsService delegate;
    private final IdentityZoneManager identityZoneManager;

    private static final String CLIENT_FIELDS = "client_id, client_secret, resource_ids, scope, "
            + "authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, "
            + "refresh_token_validity, additional_information, autoapprove, lastmodified";

    public static final String CLIENT_DETAILS_TABLE = "oauth_client_details";
    private static final String BASE_FIND_STATEMENT = "select " + CLIENT_FIELDS
            + " from " + CLIENT_DETAILS_TABLE;

    public JdbcQueryableClientDetailsService(
            final @Qualifier("jdbcClientDetailsService") MultitenantJdbcClientDetailsService delegate,
            final @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
            final NamedParameterJdbcTemplate jdbcTemplate,
            final JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate, pagingListFactory, new ClientDetailsRowMapper());
        this.identityZoneManager = identityZoneManager;
        this.delegate = delegate;
    }

    @Override
    protected String getBaseSqlQuery() {
        return BASE_FIND_STATEMENT;
    }

    @Override
    protected String getTableName() {
        return CLIENT_DETAILS_TABLE;
    }

    @Override
    public List<ClientDetails> retrieveAll(String zoneId) {
        return delegate.listClientDetails(zoneId);
    }

    @Override
    public ClientDetails retrieve(String id, String zoneId) {
        return delegate.loadClientByClientId(id, zoneId);
    }

    @Override
    public ClientDetails create(ClientDetails resource, String zoneId) {
        delegate.addClientDetails(resource, zoneId);
        return delegate.loadClientByClientId(resource.getClientId(), zoneId);
    }

    @Override
    public ClientDetails update(String id, ClientDetails resource, String zoneId) {
        delegate.updateClientDetails(resource, zoneId);
        return delegate.loadClientByClientId(id, zoneId);
    }

    @Override
    public ClientDetails delete(String id, int version, String zoneId) {
        ClientDetails client = delegate.loadClientByClientId(id, zoneId);
        delegate.onApplicationEvent(new EntityDeletedEvent<>(client, SecurityContextHolder.getContext().getAuthentication(), identityZoneManager.getCurrentIdentityZoneId()));
        return client;
    }

    @Override
    protected void validateOrderBy(String orderBy) throws IllegalArgumentException {
        super.validateOrderBy(orderBy, CLIENT_FIELDS.replace("client_secret,", ""));
    }

    private static class ClientDetailsRowMapper implements RowMapper<ClientDetails> {

        @Override
        public ClientDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
            UaaClientDetails details = new UaaClientDetails(rs.getString(1), rs.getString(3), rs.getString(4),
                    rs.getString(5), rs.getString(7), rs.getString(6));
            details.setClientSecret(rs.getString(2));
            if (rs.getObject(8) != null) {
                details.setAccessTokenValiditySeconds(rs.getInt(8));
            }
            if (rs.getObject(9) != null) {
                details.setRefreshTokenValiditySeconds(rs.getInt(9));
            }
            String json = rs.getString(10);
            if (json != null) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> additionalInformation = JsonUtils.readValue(json, Map.class);
                    details.setAdditionalInformation(additionalInformation);
                } catch (Exception e) {
                    logger.warn("Could not decode JSON for additional information: {}", details, e);
                }
            }
            String scopes = rs.getString(11);
            if (scopes != null) {
                details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet(scopes));
            }
            if (rs.getTimestamp(12) != null) {
                details.addAdditionalInformation("lastModified", rs.getTimestamp(12));
            }
            return details;
        }
    }
}
