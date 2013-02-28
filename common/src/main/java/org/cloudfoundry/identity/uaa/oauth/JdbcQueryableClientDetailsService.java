package org.cloudfoundry.identity.uaa.oauth;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.rest.jdbc.AbstractQueryable;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.JdbcClientDetailsService;

public class JdbcQueryableClientDetailsService extends AbstractQueryable<ClientDetails> implements QueryableResourceManager<ClientDetails> {

	private static final Log logger = LogFactory.getLog(JdbcQueryableClientDetailsService.class);

	private JdbcClientDetailsService delegate;

	private static final String CLIENT_FIELDS_FOR_UPDATE = "resource_ids, scope, "
																   + "authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, "
																   + "refresh_token_validity, additional_information";

	private static final String CLIENT_FIELDS = "client_secret, " + CLIENT_FIELDS_FOR_UPDATE;

	private static final String BASE_FIND_STATEMENT = "select client_id, " + CLIENT_FIELDS
															  + " from oauth_client_details";

	public JdbcQueryableClientDetailsService(JdbcClientDetailsService delegate, JdbcTemplate jdbcTemplate) {
		super(jdbcTemplate, new ClientDetailsRowMapper());
		this.delegate = delegate;
	}

	@Override
	protected String getBaseSqlQuery() {
		return BASE_FIND_STATEMENT;
	}

	@Override
	public List<ClientDetails> query(String filter) {
		return super.query(filter);
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
		private ObjectMapper mapper = new ObjectMapper();

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
					Map<String, Object> additionalInformation = mapper.readValue(json, Map.class);
					details.setAdditionalInformation(additionalInformation);
				}
				catch (Exception e) {
					logger.warn("Could not decode JSON for additional information: " + details, e);
				}
			}
			return details;
		}
	}
}
