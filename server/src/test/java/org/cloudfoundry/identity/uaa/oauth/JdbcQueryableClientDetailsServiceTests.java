package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.client.JdbcQueryableClientDetailsService;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

@WithDatabaseContext
@ExtendWith(PollutionPreventionExtension.class)
class JdbcQueryableClientDetailsServiceTests {

    private JdbcQueryableClientDetailsService jdbcQueryableClientDetailsService;

    private static final String INSERT_SQL = "insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, identity_zone_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private MultitenantJdbcClientDetailsService multitenantJdbcClientDetailsService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        multitenantJdbcClientDetailsService = new MultitenantJdbcClientDetailsService(
                jdbcTemplate,
                null,
                passwordEncoder);
        jdbcQueryableClientDetailsService = new JdbcQueryableClientDetailsService(
                multitenantJdbcClientDetailsService,
                jdbcTemplate,
                new JdbcPagingListFactory(
                        jdbcTemplate,
                        limitSqlAdapter));
    }

    @AfterEach
    void tearDown(@Autowired ApplicationContext applicationContext) {
        TestUtils.restoreToDefaults(applicationContext);
    }

    private static void addClients(
            final JdbcTemplate jdbcTemplate,
            final String zoneId
    ) {
        addClient(jdbcTemplate, zoneId, "cf", "cc", "cc.read,cc.write", "implicit", "cc.read,cc.write", 200);
        addClient(jdbcTemplate, zoneId, "scimadmin", "uaa,scim", "uaa.admin,scim.read,scim.write", "client_credentials",
                "scim.read,scim.write", 200);
        addClient(jdbcTemplate, zoneId, "admin", "tokens,clients", "clients.read,clients.write,scim.read,scim.write",
                "client_credentials", "clients.read,clients.write,scim.read,scim.write", 200);
        addClient(jdbcTemplate, zoneId, "app", "cc", "cc.read,scim.read,openid", GRANT_TYPE_AUTHORIZATION_CODE,
                "cc.read,scim.read,openid", 500);
    }

    private static void addClient(
            final JdbcTemplate jdbcTemplate,
            final String zoneId,
            final String id,
            final String resource,
            final String scope,
            final String grantType,
            final String authority,
            final long refreshTokenValidity
    ) {
        jdbcTemplate.update(
                INSERT_SQL,
                id,
                "secret",
                resource,
                scope,
                grantType,
                "myRedirectUri",
                authority,
                (long) 100,
                refreshTokenValidity,
                zoneId);
    }

    @Test
    void queryEquals() {
        verifyScimEquality(jdbcTemplate, jdbcQueryableClientDetailsService, "zoneOneId");
    }

    @Test
    void queryExists() {
        verifyScimPresent(jdbcTemplate, jdbcQueryableClientDetailsService, "zoneOneId");
    }

    @Test
    void queryEqualsInAnotherZone() {
        verifyScimEquality(jdbcTemplate, jdbcQueryableClientDetailsService, "zoneOneId");
        verifyScimEquality(jdbcTemplate, jdbcQueryableClientDetailsService, "otherZoneId");
        assertEquals(8, multitenantJdbcClientDetailsService.getTotalCount());
    }

    @Test
    void queryExistsInAnotherZone() {
        verifyScimPresent(jdbcTemplate, jdbcQueryableClientDetailsService, "zoneOneId");
        verifyScimPresent(jdbcTemplate, jdbcQueryableClientDetailsService, "otherZoneId");
        assertEquals(8, multitenantJdbcClientDetailsService.getTotalCount());
    }

    @Test
    void throwsExceptionWhenSortByIncludesPrivateFieldClientSecret() {
        assertThrowsWithMessageThat(IllegalArgumentException.class,
                () -> jdbcQueryableClientDetailsService.query("client_id pr", "client_id,client_secret", true, "zoneOneId").size(),
                is("Invalid sort field: client_secret")
        );
    }

    private static void verifyScimEquality(
            final JdbcTemplate jdbcTemplate,
            final JdbcQueryableClientDetailsService jdbcQueryableClientDetailsService,
            final String zoneId) {
        addClients(jdbcTemplate, zoneId);
        assertEquals(4, jdbcQueryableClientDetailsService.retrieveAll(zoneId).size());
        assertEquals(2, jdbcQueryableClientDetailsService.query("authorized_grant_types eq \"client_credentials\"", zoneId).size());
    }

    private static void verifyScimPresent(
            final JdbcTemplate jdbcTemplate,
            final JdbcQueryableClientDetailsService jdbcQueryableClientDetailsService,
            final String zoneId) {
        addClients(jdbcTemplate, zoneId);
        assertEquals(4, jdbcQueryableClientDetailsService.retrieveAll(zoneId).size());
        assertEquals(4, jdbcQueryableClientDetailsService.query("scope pr", zoneId).size());
    }

}
