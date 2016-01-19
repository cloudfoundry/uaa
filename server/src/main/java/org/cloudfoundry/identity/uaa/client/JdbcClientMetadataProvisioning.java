package org.cloudfoundry.identity.uaa.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.provider.IdpAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.Assert;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class JdbcClientMetadataProvisioning implements ClientMetadataProvisioning {

    private static final Log logger = LogFactory.getLog(JdbcClientMetadataProvisioning.class);

    private static final String CLIENT_METADATA_FIELDS = "id, client_id, identity_zone_id, show_on_home_page, app_launch_url, app_icon, version";
    private static final String CLIENT_METADATA_QUERY = "select " + CLIENT_METADATA_FIELDS + " from oauth_client_metadata where client_id=? and identity_zone_id=?";
    private static final String CLIENT_METADATA_CREATE = "insert into oauth_client_metadata(" + CLIENT_METADATA_FIELDS + ") values (?,?,?,?,?,?,?)";
    private static final String CLIENT_METADATA_UPDATE_FIELDS = "show_on_home_page, app_launch_url, app_icon, version";
    private static final String CLIENT_METADATA_UPDATE = "update oauth_client_metadata set " + CLIENT_METADATA_UPDATE_FIELDS.replace(",", "=?,") + "=?" + " where client_id=? and identity_zone_id=? and version=?";
    private static final String CLIENT_METADATA_DELETE_QUERY = "delete from oauth_client_metadata where client_id=? and identity_zone_id=?";

    private JdbcTemplate template;
    private final RowMapper<ClientMetadata> mapper = new ClientMetadataRowMapper();

    JdbcClientMetadataProvisioning(JdbcTemplate template) {
        Assert.notNull(template);
        this.template = template;
    }

    public void setTemplate(JdbcTemplate template) {
        this.template = template;
    }

    @Override
    public List<ClientMetadata> retrieveAll() {
        logger.debug("Retrieving UI details for all client");
        return template.query(CLIENT_METADATA_QUERY, mapper, IdentityZoneHolder.get().getId());
    }

    @Override
    public ClientMetadata retrieve(String clientId) {
        logger.debug("Retrieving UI details for client: " + clientId);
        try {
            return template.queryForObject(CLIENT_METADATA_QUERY, mapper, clientId, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException erdae) {
            throw new ClientMetadataNotFoundException("No existing metadata found for client " + clientId);
        }
    }

    @Override
    public ClientMetadata create(ClientMetadata resource) {
        logger.debug("Creating new UI details for client: " + resource.getClientId());
        final String id = UUID.randomUUID().toString();
        try {
            template.update(CLIENT_METADATA_CREATE, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    int pos = 1;
                    ps.setString(pos++, id);
                    ps.setString(pos++, resource.getClientId());
                    ps.setString(pos++, IdentityZoneHolder.get().getId());
                    ps.setBoolean(pos++, resource.isShowOnHomePage());
                    URL appLaunchUrl = resource.getAppLaunchUrl();
                    ps.setString(pos++, appLaunchUrl == null ? null : appLaunchUrl.toString());
                    String appIcon = resource.getAppIcon();
                    if (appIcon != null) {
                        byte[] decodedAppIcon = Base64.decode(appIcon.getBytes());
                        ps.setBinaryStream(pos++, new ByteArrayInputStream(decodedAppIcon), (int) decodedAppIcon.length);
                    } else {
                        ps.setBinaryStream(pos++, new ByteArrayInputStream(new byte[] {}), (int) 0);
                    }
                    ps.setInt(pos++, 1);
                }
            });
        } catch (DuplicateKeyException e) {
            throw new IdpAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }
        return retrieve(resource.getClientId());
    }

    @Override
    public ClientMetadata update(String clientId, ClientMetadata resource) {
        logger.debug("Updating metadata for client: " + clientId);
        int updated = template.update(CLIENT_METADATA_UPDATE, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                ps.setBoolean(pos++, resource.isShowOnHomePage());
                URL appLaunchUrl = resource.getAppLaunchUrl();
                ps.setString(pos++, appLaunchUrl == null ? null : appLaunchUrl.toString());
                String appIcon = resource.getAppIcon();
                if (appIcon != null) {
                    byte[] decodedAppIcon = Base64.decode(appIcon.getBytes());
                    ps.setBinaryStream(pos++, new ByteArrayInputStream(decodedAppIcon), (int) decodedAppIcon.length);
                } else {
                    ps.setBinaryStream(pos++, new ByteArrayInputStream(new byte[] {}), (int) 0);
                }
                ps.setInt(pos++, resource.getVersion() + 1);
                ps.setString(pos++, clientId);
                ps.setString(pos++, IdentityZoneHolder.get().getId());
                ps.setInt(pos++, resource.getVersion());
            }
        });

        ClientMetadata resultingClientMetadata = retrieve(clientId);

        if (updated == 0) {
            throw new OptimisticLockingFailureException(String.format(
                    "Attempt to update the UI details of client (%s) failed with incorrect version: expected=%d but found=%d",
                    clientId,
                    resultingClientMetadata.getVersion(),
                    resource.getVersion()));
        } else if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }

        return resultingClientMetadata;
    }

    @Override
    public ClientMetadata delete(String clientId, int version) {
        logger.debug("Deleting UI details for client: " + clientId);
        ClientMetadata clientMetadata = retrieve(clientId);
        int updated;

        if (version < 0) {
            updated = template.update(CLIENT_METADATA_DELETE_QUERY, clientId, IdentityZoneHolder.get().getId());
        } else {
            updated = template.update(CLIENT_METADATA_DELETE_QUERY + " and version=?", clientId, IdentityZoneHolder.get().getId(), version);
        }

        if (updated == 0) {
            throw new OptimisticLockingFailureException(String.format(
                    "Attempt to delete the UI details of client (%s) failed with incorrect version: expected=%d but found=%d",
                    clientId,
                    clientMetadata.getVersion(),
                    version));
        }

        return clientMetadata;
    }


    private class ClientMetadataRowMapper implements RowMapper<ClientMetadata> {

        @Override
        public ClientMetadata mapRow(ResultSet rs, int rowNum) throws SQLException {
            ClientMetadata clientMetadata = new ClientMetadata();
            int pos = 1;
            pos++; // id
            clientMetadata.setClientId(rs.getString(pos++));
            clientMetadata.setIdentityZoneId(rs.getString(pos++));
            clientMetadata.setShowOnHomePage(rs.getBoolean(pos++));
            try {
                clientMetadata.setAppLaunchUrl(new URL(rs.getString(pos++)));
            } catch (MalformedURLException mue) {
                // it is safe to ignore this as client_metadata rows are always created from a ClientMetadata instance whose launch url property is strongly typed to URL
            }
            clientMetadata.setAppIcon(new String(Base64.encode(rs.getBytes(pos++))));
            clientMetadata.setVersion(rs.getInt(pos++));
            return clientMetadata;
        }
    }
}
