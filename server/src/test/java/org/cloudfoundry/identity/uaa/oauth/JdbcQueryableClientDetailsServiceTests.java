package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.client.JdbcQueryableClientDetailsService;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

@WithDatabaseContext
class JdbcQueryableClientDetailsServiceTests {

    private JdbcQueryableClientDetailsService service;

    private static final String INSERT_SQL = "insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, identity_zone_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private IdentityZone otherZone;
    private MultitenantJdbcClientDetailsService delegate;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void initJdbcScimClientDetailsServiceTests() {
        delegate = new MultitenantJdbcClientDetailsService(jdbcTemplate, null, passwordEncoder);
        service = new JdbcQueryableClientDetailsService(delegate, jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate,
                limitSqlAdapter));

        JdbcIdentityZoneProvisioning zoneDb = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        otherZone = MultitenancyFixture.identityZone("other-zone-id", "myzone");
        zoneDb.create(otherZone);
    }

    @AfterEach
    void tearDown(@Autowired ApplicationContext applicationContext) {
        TestUtils.restoreToDefaults(applicationContext);
    }

    private void addClients() {
        addClient(jdbcTemplate, IdentityZoneHolder.get().getId(), "cf", "cc", "cc.read,cc.write", "implicit", "cc.read,cc.write", 200);
        addClient(jdbcTemplate, IdentityZoneHolder.get().getId(), "scimadmin", "uaa,scim", "uaa.admin,scim.read,scim.write", "client_credentials",
                "scim.read,scim.write", 200);
        addClient(jdbcTemplate, IdentityZoneHolder.get().getId(), "admin", "tokens,clients", "clients.read,clients.write,scim.read,scim.write",
                "client_credentials", "clients.read,clients.write,scim.read,scim.write", 200);
        addClient(jdbcTemplate, IdentityZoneHolder.get().getId(), "app", "cc", "cc.read,scim.read,openid", GRANT_TYPE_AUTHORIZATION_CODE,
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
        addClients();
        assertEquals(4, service.retrieveAll(IdentityZoneHolder.get().getId()).size());
        assertEquals(2, service.query("authorized_grant_types eq \"client_credentials\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    void queryExists() {
        addClients();
        assertEquals(4, service.retrieveAll(IdentityZoneHolder.get().getId()).size());
        assertEquals(4, service.query("scope pr", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    void queryEqualsInAnotherZone() {
        queryEquals();
        IdentityZoneHolder.set(otherZone);
        queryEquals();
        assertEquals(8, delegate.getTotalCount());
    }

    @Test
    void queryExistsInAnotherZone() {
        queryExists();
        IdentityZoneHolder.set(otherZone);
        queryExists();
        assertEquals(8, delegate.getTotalCount());
    }

    @Test
    void throwsExceptionWhenSortByIncludesPrivateFieldClientSecret() {
        assertThrowsWithMessageThat(IllegalArgumentException.class,
                () -> service.query("client_id pr", "client_id,client_secret", true, IdentityZoneHolder.get().getId()).size(),
                is("Invalid sort field: client_secret")
        );
    }
}
