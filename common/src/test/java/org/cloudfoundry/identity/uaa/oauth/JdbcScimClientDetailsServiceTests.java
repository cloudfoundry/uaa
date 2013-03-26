package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.provider.JdbcClientDetailsService;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb", "test,mysql"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcScimClientDetailsServiceTests {

	private JdbcQueryableClientDetailsService service;

	private JdbcTemplate jdbcTemplate;

	@Autowired
	private DataSource dataSource;

	private static final String INSERT_SQL = "insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity) values (?, ?, ?, ?, ?, ?, ?, ?, ?)";

	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
		jdbcTemplate = new JdbcTemplate(dataSource);
		JdbcClientDetailsService delegate = new JdbcClientDetailsService(dataSource);
		service = new JdbcQueryableClientDetailsService(delegate, jdbcTemplate);

		addClient("vmc", "secret", "cc", "cc.read,cc.write",
						 "implicit", "myRedirectUri", "cc.read,cc.write", 100, 200);
		addClient("scimadmin", "secret", "uaa,scim", "uaa.admin,scim.read,scim.write",
						 "client_credentials", "myRedirectUri", "scim.read,scim.write", 100, 200);
		addClient("admin", "secret", "tokens,clients", "clients.read,clients.write,scim.read,scim.write",
						 "client_credentials", "myRedirectUri", "clients.read,clients.write,scim.read,scim.write", 100, 200);
		addClient("app", "secret", "cc", "cc.read,scim.read,openid",
						 "authorization_code", "myRedirectUri", "cc.read,scim.read,openid", 100, 500);

	}

	private void addClient(String id, String secret, String resource, String scope, String grantType, String redirectUri, String authority, long accessTokenValidity, long refreshTokenValidity) {
		jdbcTemplate.update(INSERT_SQL, id, secret, resource, scope, grantType, redirectUri, authority, accessTokenValidity, refreshTokenValidity);

	}

	@After
	public void tearDown() throws Exception {
		TestUtils.deleteFrom(dataSource, "oauth_client_details");
	}

	@Test
	public void testQueryEquals() throws Exception {
		assertEquals(4, service.retrieveAll().size());
		assertEquals(2, service.query("authorized_grant_types eq 'client_credentials'").size());
	}

	@Test
	public void testQueryExists() throws Exception {
		assertEquals(4, service.retrieveAll().size());
		assertEquals(4, service.query("scope pr").size());
	}

}
