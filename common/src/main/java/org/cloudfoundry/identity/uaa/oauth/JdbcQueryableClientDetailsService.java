/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.rest.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.util.StringUtils;

public class JdbcQueryableClientDetailsService extends AbstractQueryable<ClientDetails> implements
                QueryableResourceManager<ClientDetails> {

    private static final Log logger = LogFactory.getLog(JdbcQueryableClientDetailsService.class);

    private JdbcClientDetailsService delegate;

    private static final String CLIENT_FIELDS = "client_id, client_secret, resource_ids, scope, "
                    + "authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, "
                    + "refresh_token_validity, additional_information, autoapprove, lastmodified";

    public static final String CLIENT_DETAILS_TABLE = "oauth_client_details";
    private static final String BASE_FIND_STATEMENT = "select " + CLIENT_FIELDS
        + " from " + CLIENT_DETAILS_TABLE;

    public JdbcQueryableClientDetailsService(JdbcClientDetailsService delegate, JdbcTemplate jdbcTemplate,
                    JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate, pagingListFactory, new ClientDetailsRowMapper());
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
    public List<ClientDetails> query(String filter, String sortBy, boolean ascending) {
    	if (StringUtils.hasText(filter)) {
            filter += " and";
        }
        filter += " identity_zone_id eq \""+IdentityZoneHolder.get().getId()+"\"";
    	return super.query(filter, sortBy, ascending);
    }

    @Override
    public List<ClientDetails> retrieveAll() {
        return delegate.listClientDetails();
    }

    @Override
    public ClientDetails retrieve(String id) {
        return delegate.loadClientByClientId(id);
    }

    @Override
    public ClientDetails create(ClientDetails resource) {
        delegate.addClientDetails(resource);
        return delegate.loadClientByClientId(resource.getClientId());
    }

    @Override
    public ClientDetails update(String id, ClientDetails resource) {
        delegate.updateClientDetails(resource);
        return delegate.loadClientByClientId(id);
    }

    @Override
    public ClientDetails delete(String id, int version) {
        ClientDetails client = delegate.loadClientByClientId(id);
        delegate.removeClientDetails(id);
        return client;
    }

    private static class ClientDetailsRowMapper implements RowMapper<ClientDetails> {

        @Override
        public ClientDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
            BaseClientDetails details = new BaseClientDetails(rs.getString(1), rs.getString(3), rs.getString(4),
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
                    logger.warn("Could not decode JSON for additional information: " + details, e);
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
