package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.common.util.DefaultJdbcListFactory;
import org.cloudfoundry.identity.uaa.oauth.common.util.JdbcListFactory;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.security.ContextSensitiveOAuth2SecurityExpressionMethods;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
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

    private static final String CLIENT_FIELDS = "client_secret, client_jwt_config, " + CLIENT_FIELDS_FOR_UPDATE;

    private static final String BASE_FIND_STATEMENT =
            "select client_id, " + CLIENT_FIELDS + " from oauth_client_details";

    private static final String DEFAULT_FIND_STATEMENT =
            BASE_FIND_STATEMENT + " where identity_zone_id = :identityZoneId order by client_id";

    private static final String DEFAULT_SELECT_STATEMENT =
            BASE_FIND_STATEMENT + " where client_id = ? and identity_zone_id = ?";

    private static final String SINGLE_SELECT_STATEMENT =
            "select client_id from oauth_client_details where client_id = ? and identity_zone_id = ?";

    private static final String DEFAULT_INSERT_STATEMENT =
            "insert into oauth_client_details (" + CLIENT_FIELDS
                    + ", client_id, identity_zone_id, created_by) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private static final String BASE_UPDATE_STATEMENT =
            "update oauth_client_details set ";

    private static final String DEFAULT_UPDATE_STATEMENT =
            BASE_UPDATE_STATEMENT + CLIENT_FIELDS_FOR_UPDATE.replace(", ", "=?, ")
                    + "=? where client_id = ? and identity_zone_id = ?";

    private static final String DEFAULT_UPDATE_SECRET_STATEMENT =
            BASE_UPDATE_STATEMENT + "client_secret = ? where client_id = ? and identity_zone_id = ?";

    private static final String DEFAULT_UPDATE_CLIENT_JWT_CONFIG_STATEMENT =
            BASE_UPDATE_STATEMENT + "client_jwt_config = ? where client_id = ? and identity_zone_id = ?";

    static final String DEFAULT_DELETE_STATEMENT =
            "delete from oauth_client_details where client_id = ? and identity_zone_id = ?";

    private static final String DELETE_CLIENTS_BY_ZONE =
            "delete from oauth_client_details where identity_zone_id = ?";
    private static final String NO_CLIENT_FOUND_WITH_ID = "No client found with id = ";

    private RowMapper<ClientDetails> rowMapper = new ClientDetailsRowMapper();

    private String selectClientDetailsSql = DEFAULT_SELECT_STATEMENT;

    private final PasswordEncoder passwordEncoder;

    private final JdbcTemplate jdbcTemplate;

    private JdbcListFactory listFactory;

    public MultitenantJdbcClientDetailsService(
            final NamedParameterJdbcTemplate jdbcTemplate,
            final IdentityZoneManager identityZoneManager,
            final @Qualifier("cachingPasswordEncoder") PasswordEncoder passwordEncoder) {
        super(identityZoneManager);
        Assert.notNull(jdbcTemplate, "JDbcTemplate required");
        this.jdbcTemplate = jdbcTemplate.getJdbcTemplate();
        this.listFactory = new DefaultJdbcListFactory(jdbcTemplate);
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
        if (exists(clientDetails.getClientId(), zoneId)) {
            throw new ClientAlreadyExistsException("Client already exists: " + clientDetails.getClientId());
        }
        jdbcTemplate.update(DEFAULT_INSERT_STATEMENT, getInsertClientDetailsFields(clientDetails, zoneId));
    }

    private boolean exists(String clientId, String zoneId) {
        List<String> idResults = jdbcTemplate.queryForList(SINGLE_SELECT_STATEMENT, String.class, clientId, zoneId);
        return idResults != null && idResults.size() == 1;
    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails, String zoneId) throws NoSuchClientException {
        int count = jdbcTemplate.update(DEFAULT_UPDATE_STATEMENT, getFieldsForUpdate(clientDetails, zoneId));
        if (count != 1) {
            throw new NoSuchClientException(NO_CLIENT_FOUND_WITH_ID + clientDetails.getClientId() + " in identity zone id=" + zoneId);
        }
    }

    @Override
    public void updateClientSecret(String clientId, String secret, String zoneId) throws NoSuchClientException {
        int count = jdbcTemplate.update(DEFAULT_UPDATE_SECRET_STATEMENT, secret != null ? passwordEncoder.encode(secret) : null, clientId, zoneId);
        if (count != 1) {
            throw new NoSuchClientException(NO_CLIENT_FOUND_WITH_ID + clientId);
        }
    }

    @Override
    public void updateClientJwtConfig(String clientId, String keyConfig, String zoneId) throws NoSuchClientException {
        int count = jdbcTemplate.update(DEFAULT_UPDATE_CLIENT_JWT_CONFIG_STATEMENT, keyConfig, clientId, zoneId);
        if (count != 1) {
            throw new NoSuchClientException(NO_CLIENT_FOUND_WITH_ID + clientId);
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
        Object[] clientDetailFieldsForUpdate = new Object[fieldsForUpdate.length + 3];
        System.arraycopy(fieldsForUpdate, 0, clientDetailFieldsForUpdate, 2, fieldsForUpdate.length);
        clientDetailFieldsForUpdate[0] =
                clientDetails.getClientSecret() != null ?
                        passwordEncoder.encode(clientDetails.getClientSecret()) :
                        null;
        clientDetailFieldsForUpdate[1] = clientDetails instanceof UaaClientDetails ucd ? ucd.getClientJwtConfig() : null;
        clientDetailFieldsForUpdate[clientDetailFieldsForUpdate.length - 1] = getUserId();
        return clientDetailFieldsForUpdate;
    }

    private Object[] getFieldsForUpdate(ClientDetails clientDetails, String zoneId) {

        Map<String, Object> additionalInformation = new HashMap<>(clientDetails.getAdditionalInformation());
        Collection<String> requiredGroups = (Collection<String>) additionalInformation.remove(REQUIRED_USER_GROUPS);

        String json;
        try {

            json = JsonUtils.writeValueAsString(additionalInformation);
        } catch (Exception e) {
            logger.warn("Could not serialize additional information: {}", clientDetails, e);
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
        Set<String> scopes = new HashSet<>();
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
            throw new NoSuchClientException(NO_CLIENT_FOUND_WITH_ID + clientId);
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
            throw new NoSuchClientException(NO_CLIENT_FOUND_WITH_ID + clientId);
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

    @Override
    public void addClientJwtConfig(String clientId, String keyConfig, String zoneId, boolean overwrite) throws NoSuchClientException {
        ClientJwtConfiguration clientJwtConfiguration = ClientJwtConfiguration.parse(keyConfig);
        if (clientJwtConfiguration != null) {
            UaaClientDetails uaaUaaClientDetails = (UaaClientDetails) loadClientByClientId(clientId, zoneId);
            ClientJwtConfiguration existingConfig = ClientJwtConfiguration.readValue(uaaUaaClientDetails);
            ClientJwtConfiguration result = ClientJwtConfiguration.merge(existingConfig, clientJwtConfiguration, overwrite);
            if (result != null) {
                updateClientJwtConfig(clientId, JsonUtils.writeValueAsString(result), zoneId);
            }
        } else {
            throw new InvalidClientDetailsException("Invalid jwt configuration configuration");
        }
    }

    @Override
    public void addClientJwtCredential(String clientId, ClientJwtCredential keyConfig, String zoneId, boolean overwrite)
            throws NoSuchClientException {
        UaaClientDetails uaaUaaClientDetails = (UaaClientDetails) loadClientByClientId(clientId, zoneId);
        ClientJwtConfiguration existingConfig = uaaUaaClientDetails != null ? ClientJwtConfiguration.readValue(uaaUaaClientDetails) : null;
        ClientJwtConfiguration clientJwtConfiguration = new ClientJwtConfiguration(List.of(keyConfig));
        ClientJwtConfiguration result = ClientJwtConfiguration.merge(existingConfig, clientJwtConfiguration, overwrite);
        if (result != null) {
            updateClientJwtConfig(clientId, JsonUtils.writeValueAsString(result), zoneId);
        }
    }

    @Override
    public void deleteClientJwtConfig(String clientId, String keyConfig, String zoneId) throws NoSuchClientException {
        ClientJwtConfiguration clientJwtConfiguration;
        if (UaaUrlUtils.isUrl(keyConfig)) {
            clientJwtConfiguration = ClientJwtConfiguration.parse(keyConfig);
        } else {
            clientJwtConfiguration = new ClientJwtConfiguration(keyConfig, null);
        }
        if (clientJwtConfiguration != null) {
            UaaClientDetails uaaUaaClientDetails = (UaaClientDetails) loadClientByClientId(clientId, zoneId);
            ClientJwtConfiguration result = ClientJwtConfiguration.delete(ClientJwtConfiguration.readValue(uaaUaaClientDetails), clientJwtConfiguration);
            updateClientJwtConfig(clientId, result != null ? JsonUtils.writeValueAsString(result) : null, zoneId);
        } else {
            throw new InvalidClientDetailsException("Invalid jwt configuration configuration");
        }
    }

    @Override
    public void deleteClientJwtCredential(String clientId, ClientJwtCredential keyConfig, String zoneId) throws NoSuchClientException {
        UaaClientDetails uaaUaaClientDetails = (UaaClientDetails) loadClientByClientId(clientId, zoneId);
        ClientJwtConfiguration existingConfig = uaaUaaClientDetails != null ? ClientJwtConfiguration.readValue(uaaUaaClientDetails) : null;
        ClientJwtConfiguration clientJwtConfiguration = new ClientJwtConfiguration(List.of(keyConfig));
        ClientJwtConfiguration result = ClientJwtConfiguration.delete(existingConfig, clientJwtConfiguration);
        updateClientJwtConfig(clientId, result != null ? JsonUtils.writeValueAsString(result) : null, zoneId);
    }

    /**
     * Row mapper for ClientDetails.
     *
     * @author Dave Syer
     */
    private static class ClientDetailsRowMapper implements RowMapper<ClientDetails> {
        public ClientDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
            UaaClientDetails details = new UaaClientDetails(
                    rs.getString(1),
                    rs.getString(4),
                    rs.getString(5),
                    rs.getString(6),
                    rs.getString(8),
                    rs.getString(7)
            );
            details.setClientSecret(rs.getString(2));
            details.setClientJwtConfig(rs.getString(3));
            if (rs.getObject(9) != null) {
                details.setAccessTokenValiditySeconds(rs.getInt(9));
            }
            if (rs.getObject(10) != null) {
                details.setRefreshTokenValiditySeconds(rs.getInt(10));
            }
            String json = rs.getString(11);
            String scopes = rs.getString(12);
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
                        if (autoApprovedFromAddInfo instanceof Boolean boolean1 && boolean1 || "true".equals(autoApprovedFromAddInfo)) {
                            autoApproveScopes.add("true");
                        } else if (autoApprovedFromAddInfo instanceof Collection<?>) {
                            @SuppressWarnings("unchecked")
                            Collection<? extends String> approvedScopes = (Collection<? extends String>) autoApprovedFromAddInfo;
                            autoApproveScopes.addAll(approvedScopes);
                        }
                    }

                } catch (Exception e) {
                    logger.warn("Could not decode JSON for additional information: {}", details, e);
                }
            }

            details.setAutoApproveScopes(autoApproveScopes);


            // lastModified
            if (rs.getObject(13) != null) {
                details.addAdditionalInformation("lastModified", rs.getTimestamp(13));
            }

            //required_user_groups
            String requiredUserGroups = rs.getString(14);
            if (!StringUtils.hasLength(requiredUserGroups)) {
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
        if (authentication == null) {
            return null;
        }
        if (authentication.getPrincipal() instanceof UaaPrincipal) {
            userId = ((UaaPrincipal) authentication.getPrincipal()).getId();
        } else if (authentication.getPrincipal() instanceof String) {
            ContextSensitiveOAuth2SecurityExpressionMethods contextSensitiveOAuth2SecurityExpressionMethods = new ContextSensitiveOAuth2SecurityExpressionMethods(authentication);
            userId = getCreatedByForClientAndZone((String) authentication.getPrincipal(), contextSensitiveOAuth2SecurityExpressionMethods.getAuthenticationZoneId());
        }
        return userId;
    }

    String getCreatedByForClientAndZone(String clientId, String zoneId) {
        return jdbcTemplate.queryForObject(GET_CREATED_BY_SQL, String.class, new Object[]{clientId, zoneId});
    }
}
