package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.security.ContextSensitiveOAuth2SecurityExpressionMethods;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.util.DefaultJdbcListFactory;
import org.springframework.security.oauth2.common.util.JdbcListFactory;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptySet;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;
import static org.springframework.util.StringUtils.commaDelimitedListToSet;

/**
 * A copy of JdbcClientDetailsService but with IdentityZone awareness
 */
@Component("jdbcClientDetailsService")
public class MultitenantJdbcClientDetailsService extends MultitenantClientServices implements
        ResourceMonitor<ClientDetails>,
        SystemDeletable {

    protected static final Logger logger = LoggerFactory.getLogger(MultitenantJdbcClientDetailsService.class);

    private static final String GET_CREATED_BY_SQL =
            "select created_by from oauth_client_details where client_id=? and identity_zone_id=?";

    private static final String CLIENT_FIELDS_FOR_UPDATE =
            "resource_ids, scope, " +
                    "authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, " +
                    "refresh_token_validity, additional_information, autoapprove, lastmodified, required_user_groups";

    private static final String CLIENT_FIELDS = "client_secret, " + CLIENT_FIELDS_FOR_UPDATE;

    private static final String BASE_FIND_STATEMENT =
            "select client_id, " + CLIENT_FIELDS + " from oauth_client_details";

    private static final String DEFAULT_FIND_STATEMENT =
            BASE_FIND_STATEMENT + " where identity_zone_id = :identityZoneId order by client_id";

    private static final String DEFAULT_SELECT_STATEMENT =
            BASE_FIND_STATEMENT + " where client_id = ? and identity_zone_id = ?";

    private static final String DEFAULT_INSERT_STATEMENT =
            "insert into oauth_client_details (" + CLIENT_FIELDS
                    + ", client_id, identity_zone_id, created_by) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private static final String DEFAULT_UPDATE_STATEMENT =
            "update oauth_client_details " + "set "
                    + CLIENT_FIELDS_FOR_UPDATE.replaceAll(", ", "=?, ") + "=? where client_id = ? and identity_zone_id = ?";

    private static final String DEFAULT_UPDATE_SECRET_STATEMENT =
            "update oauth_client_details "
                    + "set client_secret = ? where client_id = ? and identity_zone_id = ?";

    static final String DEFAULT_DELETE_STATEMENT =
            "delete from oauth_client_details where client_id = ? and identity_zone_id = ?";

    private static final String DELETE_CLIENTS_BY_ZONE =
            "delete from oauth_client_details where identity_zone_id = ?";

    private RowMapper<ClientDetails> rowMapper = new ClientDetailsRowMapper();

    private String selectClientDetailsSql = DEFAULT_SELECT_STATEMENT;

    private final PasswordEncoder passwordEncoder;

    private final JdbcTemplate jdbcTemplate;

    private JdbcListFactory listFactory;

    public MultitenantJdbcClientDetailsService(
            final JdbcTemplate jdbcTemplate,
            final IdentityZoneManager identityZoneManager,
            final @Qualifier("cachingPasswordEncoder") PasswordEncoder passwordEncoder) {
        super(identityZoneManager);
        Assert.notNull(jdbcTemplate, "JDbcTemplate required");
        this.jdbcTemplate = jdbcTemplate;
        this.listFactory = new DefaultJdbcListFactory(new NamedParameterJdbcTemplate(jdbcTemplate));
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId, String zoneId) throws InvalidClientException {
        ClientDetails details;
        try {
            details = jdbcTemplate.queryForObject(selectClientDetailsSql, new ClientDetailsRowMapper(), clientId, zoneId);
        } catch (EmptyResultDataAccessException | DataIntegrityViolationException e) {
            throw new NoSuchClientException("No client with requested id: " + clientId);
        }

        return details;
    }

    @Override
    public void addClientDetails(ClientDetails clientDetails, String zoneId) throws ClientAlreadyExistsException {
        try {
            jdbcTemplate.update(DEFAULT_INSERT_STATEMENT, getInsertClientDetailsFields(clientDetails, zoneId));
        } catch (DuplicateKeyException e) {
            throw new ClientAlreadyExistsException("Client already exists: " + clientDetails.getClientId(), e);
        }
    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails, String zoneId) throws NoSuchClientException {
        int count = jdbcTemplate.update(DEFAULT_UPDATE_STATEMENT, getFieldsForUpdate(clientDetails, zoneId));
        if (count != 1) {
            throw new NoSuchClientException("No client found with id = " + clientDetails.getClientId() + " in identity zone id=" + zoneId);
        }
    }

    @Override
    public void updateClientSecret(String clientId, String secret, String zoneId) throws NoSuchClientException {
        int count = jdbcTemplate.update(DEFAULT_UPDATE_SECRET_STATEMENT, passwordEncoder.encode(secret), clientId, zoneId);
        if (count != 1) {
            throw new NoSuchClientException("No client found with id = " + clientId);
        }
    }

    @Override
    public void removeClientDetails(String clientId, String zoneId) throws NoSuchClientException {
        deleteByClient(clientId, zoneId);
    }

    public List<ClientDetails> listClientDetails(String zoneId) {
        return listFactory.getList(DEFAULT_FIND_STATEMENT, Collections.singletonMap("identityZoneId", zoneId), rowMapper);
    }

    private Object[] getInsertClientDetailsFields(ClientDetails clientDetails, String zoneId) {
        Object[] fieldsForUpdate = getFieldsForUpdate(clientDetails, zoneId);
        Object[] clientDetailFieldsForUpdate = new Object[fieldsForUpdate.length + 2];
        System.arraycopy(fieldsForUpdate, 0, clientDetailFieldsForUpdate, 1, fieldsForUpdate.length);
        clientDetailFieldsForUpdate[0] =
                clientDetails.getClientSecret() != null ?
                        passwordEncoder.encode(clientDetails.getClientSecret()) :
                        null;
        clientDetailFieldsForUpdate[clientDetailFieldsForUpdate.length - 1] = getUserId();
        return clientDetailFieldsForUpdate;
    }

    private Object[] getFieldsForUpdate(ClientDetails clientDetails, String zoneId) {

        Map<String, Object> additionalInformation = new HashMap(clientDetails.getAdditionalInformation());
        Collection<String> requiredGroups = (Collection<String>) additionalInformation.remove(REQUIRED_USER_GROUPS);

        String json;
        try {

            json = JsonUtils.writeValueAsString(additionalInformation);
        } catch (Exception e) {
            logger.warn("Could not serialize additional information: " + clientDetails, e);
            throw new InvalidDataAccessResourceUsageException("Could not serialize additional information:" + clientDetails.getClientId(), e);
        }

        return new Object[]{
                collectionToString(clientDetails.getResourceIds()),
                collectionToString(clientDetails.getScope()),
                collectionToString(clientDetails.getAuthorizedGrantTypes()),
                collectionToString(clientDetails.getRegisteredRedirectUri()),
                collectionToString(clientDetails.getAuthorities()),
                clientDetails.getAccessTokenValiditySeconds(),
                clientDetails.getRefreshTokenValiditySeconds(),
                json,
                getAutoApproveScopes(clientDetails),
                new Timestamp(System.currentTimeMillis()),
                collectionToString(requiredGroups),
                clientDetails.getClientId(),
                zoneId
        };
    }

    private String collectionToString(Collection<?> collection) {
        if (collection == null || collection.isEmpty()) {
            return null;
        } else {
            return collectionToCommaDelimitedString(collection);
        }
    }

    private String getAutoApproveScopes(ClientDetails clientDetails) {
        if (clientDetails.isAutoApprove("true")) {
            return "true"; // all scopes autoapproved
        }
        Set<String> scopes = new HashSet<String>();
        for (String scope : clientDetails.getScope()) {
            if (clientDetails.isAutoApprove(scope)) {
                scopes.add(scope);
            }
        }
        return collectionToCommaDelimitedString(scopes);
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return jdbcTemplate.update(DELETE_CLIENTS_BY_ZONE, zoneId);
    }

    @Override
    public int deleteByClient(String clientId, String zoneId) {
        int count = jdbcTemplate.update(DEFAULT_DELETE_STATEMENT, clientId, zoneId);
        if (count == 0) {
            throw new NoSuchClientException("No client found with id = " + clientId);
        }
        return count;
    }

    @Override
    public Logger getLogger() {
        return logger;
    }

    @Override
    public void addClientSecret(String clientId, String newSecret, String zoneId) throws NoSuchClientException {
        ClientDetails clientDetails = loadClientByClientId(clientId, zoneId);
        String encodedNewSecret = passwordEncoder.encode(newSecret);
        StringBuilder newSecretBuilder = new StringBuilder()
                .append(clientDetails.getClientSecret() == null ? "" : clientDetails.getClientSecret() + " ")
                .append(encodedNewSecret);
        int count = jdbcTemplate.update(DEFAULT_UPDATE_SECRET_STATEMENT, newSecretBuilder.toString(), clientId, zoneId);
        if (count != 1) {
            throw new NoSuchClientException("No client found with id = " + clientId);
        }
    }

    @Override
    public void deleteClientSecret(String clientId, String zoneId) throws NoSuchClientException {
        ClientDetails clientDetails = loadClientByClientId(clientId, zoneId);
        String clientSecret = clientDetails.getClientSecret().split(" ")[1];
        int count = jdbcTemplate.update(DEFAULT_UPDATE_SECRET_STATEMENT, clientSecret, clientId, zoneId);
        if (count != 1) {
            throw new NoSuchClientException("Unable to update client with " + clientId);
        }
    }


    /**
     * Row mapper for ClientDetails.
     *
     * @author Dave Syer
     */
    private static class ClientDetailsRowMapper implements RowMapper<ClientDetails> {
        public ClientDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
            BaseClientDetails details = new BaseClientDetails(
                    rs.getString(1),
                    rs.getString(3),
                    rs.getString(4),
                    rs.getString(5),
                    rs.getString(7),
                    rs.getString(6)
            );
            details.setClientSecret(rs.getString(2));
            if (rs.getObject(8) != null) {
                details.setAccessTokenValiditySeconds(rs.getInt(8));
            }
            if (rs.getObject(9) != null) {
                details.setRefreshTokenValiditySeconds(rs.getInt(9));
            }
            String json = rs.getString(10);
            String scopes = rs.getString(11);
            Set<String> autoApproveScopes = new HashSet<>();
            if (scopes != null) {
                autoApproveScopes = commaDelimitedListToSet(scopes);
            }
            if (json != null) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> additionalInformation = JsonUtils.readValue(json, Map.class);
                    Object autoApprovedFromAddInfo = additionalInformation.remove(ClientConstants.AUTO_APPROVE);
                    details.setAdditionalInformation(additionalInformation);
                    if (autoApprovedFromAddInfo != null) {
                        if ((autoApprovedFromAddInfo instanceof Boolean && (Boolean) autoApprovedFromAddInfo || "true".equals(autoApprovedFromAddInfo))) {
                            autoApproveScopes.add("true");
                        } else if (autoApprovedFromAddInfo instanceof Collection<?>) {
                            @SuppressWarnings("unchecked")
                            Collection<? extends String> approvedScopes = (Collection<? extends String>) autoApprovedFromAddInfo;
                            autoApproveScopes.addAll(approvedScopes);
                        }
                    }

                } catch (Exception e) {
                    logger.warn("Could not decode JSON for additional information: " + details, e);
                }
            }

            details.setAutoApproveScopes(autoApproveScopes);


            // lastModified
            if (rs.getObject(12) != null) {
                details.addAdditionalInformation("lastModified", rs.getTimestamp(12));
            }

            //required_user_groups
            String requiredUserGroups = rs.getString(13);
            if (StringUtils.isEmpty(requiredUserGroups)) {
                details.addAdditionalInformation(REQUIRED_USER_GROUPS, emptySet());
            } else {
                details.addAdditionalInformation(REQUIRED_USER_GROUPS, commaDelimitedListToSet(requiredUserGroups));
            }

            return details;
        }
    }

    @Override
    public int getTotalCount() {
        Integer count = jdbcTemplate.queryForObject("select count(*) from oauth_client_details", Integer.class);
        if (count != null) {
            return count;
        }
        return 0;
    }

    protected String getUserId() {
        String userId = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        //Bootstrap will not have authenticated session
        if (authentication == null) return null;
        if (authentication.getPrincipal() instanceof UaaPrincipal) {
            userId = ((UaaPrincipal) authentication.getPrincipal()).getId();
        } else if (authentication.getPrincipal() instanceof String) {
            ContextSensitiveOAuth2SecurityExpressionMethods contextSensitiveOAuth2SecurityExpressionMethods = new ContextSensitiveOAuth2SecurityExpressionMethods(authentication);
            userId = getCreatedByForClientAndZone((String) authentication.getPrincipal(), contextSensitiveOAuth2SecurityExpressionMethods.getAuthenticationZoneId());
        }
        return userId;
    }

    String getCreatedByForClientAndZone(String clientId, String zoneId) {
        return jdbcTemplate.queryForObject(GET_CREATED_BY_SQL, new Object[]{clientId, zoneId}, String.class);
    }
}
