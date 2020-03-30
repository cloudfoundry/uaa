package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.CLIENT_NAME;
import static org.springframework.util.StringUtils.hasText;

@Component("jdbcClientMetadataProvisioning")
public class JdbcClientMetadataProvisioning implements ClientMetadataProvisioning {

    private static final Logger logger = LoggerFactory.getLogger(JdbcClientMetadataProvisioning.class);

    private static final String CLIENT_METADATA_FIELDS = "client_id, identity_zone_id, show_on_home_page, app_launch_url, app_icon, additional_information, created_by";
    private static final String CLIENT_METADATA_QUERY = "select " + CLIENT_METADATA_FIELDS + " from oauth_client_details where client_id=? and identity_zone_id=?";
    private static final String CLIENT_METADATAS_QUERY = "select " + CLIENT_METADATA_FIELDS + " from oauth_client_details where identity_zone_id=? and (app_launch_url is not null or app_icon is not null)";
    private static final String CLIENT_METADATA_UPDATE_FIELDS = "show_on_home_page, app_launch_url, app_icon";
    private static final String CLIENT_METADATA_UPDATE = "update oauth_client_details set " + CLIENT_METADATA_UPDATE_FIELDS.replace(",", "=?,") + "=?" + " where client_id=? and identity_zone_id=?";

    private final MultitenantClientServices clientDetailsService;
    private final JdbcTemplate jdbcTemplate;
    private final RowMapper<ClientMetadata> mapper = new ClientMetadataRowMapper();

    JdbcClientMetadataProvisioning(
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            final JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate);
        Assert.notNull(clientDetailsService);
        this.jdbcTemplate = jdbcTemplate;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public List<ClientMetadata> retrieveAll(String zoneId) {
        logger.debug("Retrieving UI details for all client");
        return jdbcTemplate.query(CLIENT_METADATAS_QUERY, mapper, zoneId);
    }

    @Override
    public ClientMetadata retrieve(String clientId, String zoneId) {
        logger.debug("Retrieving UI details for client: " + clientId);
        return jdbcTemplate.queryForObject(CLIENT_METADATA_QUERY, mapper, clientId, zoneId);
    }

    @Override
    public ClientMetadata update(ClientMetadata resource, String zoneId) {
        logger.debug("Updating metadata for client: " + resource.getClientId());

        updateClientNameIfNotEmpty(resource, zoneId);
        int updated = jdbcTemplate.update(CLIENT_METADATA_UPDATE, ps -> {
            int pos = 1;
            ps.setBoolean(pos++, resource.isShowOnHomePage());
            URL appLaunchUrl = resource.getAppLaunchUrl();
            ps.setString(pos++, appLaunchUrl == null ? null : appLaunchUrl.toString());
            String appIcon = resource.getAppIcon();
            if (appIcon != null) {
                byte[] decodedAppIcon = Base64Utils.decode(appIcon.getBytes());
                ps.setBinaryStream(pos++, new ByteArrayInputStream(decodedAppIcon), decodedAppIcon.length);
            } else {
                ps.setBinaryStream(pos++, new ByteArrayInputStream(new byte[]{}), 0);
            }
            ps.setString(pos++, resource.getClientId());
            ps.setString(pos++, zoneId);
        });

        ClientMetadata resultingClientMetadata = retrieve(resource.getClientId(), zoneId);

        if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }

        return resultingClientMetadata;
    }

    protected void updateClientNameIfNotEmpty(ClientMetadata resource, String zoneId) {
        //we don't remove it, only set values
        if (hasText(resource.getClientName())) {
            BaseClientDetails client = (BaseClientDetails) clientDetailsService.loadClientByClientId(resource.getClientId(), zoneId);
            client.addAdditionalInformation(CLIENT_NAME, resource.getClientName());
            clientDetailsService.updateClientDetails(client, zoneId);
        }
    }

    private class ClientMetadataRowMapper implements RowMapper<ClientMetadata> {

        @Override
        public ClientMetadata mapRow(ResultSet rs, int rowNum) throws SQLException {
            ClientMetadata clientMetadata = new ClientMetadata();
            int pos = 1;
            clientMetadata.setClientId(rs.getString("client_id"));
            clientMetadata.setIdentityZoneId(rs.getString("identity_zone_id"));
            clientMetadata.setShowOnHomePage(rs.getBoolean("show_on_home_page"));
            try {
                clientMetadata.setAppLaunchUrl(new URL(rs.getString("app_launch_url")));
            } catch (MalformedURLException mue) {
                // it is safe to ignore this as client_metadata rows are always created from a ClientMetadata instance whose launch url property is strongly typed to URL
            }
            byte[] iconBytes = rs.getBytes("app_icon");
            if (iconBytes != null) {
                clientMetadata.setAppIcon(new String(Base64Utils.encode(iconBytes)));
            }
            clientMetadata.setCreatedBy(rs.getString("created_by"));
            String json = rs.getString("additional_information");
            if (hasText(json)) {
                Map<String, Object> additionalInformation = JsonUtils.readValue(json, new TypeReference<Map<String, Object>>() {
                });
                clientMetadata.setClientName((String) additionalInformation.get(CLIENT_NAME));
            }
            return clientMetadata;
        }
    }
}
