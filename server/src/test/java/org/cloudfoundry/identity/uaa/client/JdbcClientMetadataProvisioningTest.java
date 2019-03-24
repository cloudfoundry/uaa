package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.net.URL;
import java.util.List;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class JdbcClientMetadataProvisioningTest extends JdbcTestBase {

    private static final String CLIENT_NAME = "Test name";
    private JdbcClientMetadataProvisioning db;

    private String randomGUID = "4097895b-ebc1-4732-b6e5-2c33dd2c7cd1";
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);

    @Before
    public void createDatasource() {
        MultitenantJdbcClientDetailsService clientService = new MultitenantJdbcClientDetailsService(jdbcTemplate);
        db = new JdbcClientMetadataProvisioning(clientService, jdbcTemplate);
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void constraintViolation_WhenNoMatchingClientFound() throws Exception {
        ClientMetadata clientMetadata = createTestClientMetadata(generator.generate(), true, new URL("http://app.launch/url"), base64EncodedImg);
        db.update(clientMetadata, IdentityZoneHolder.get().getId());
    }

    @Test
    public void retrieveClientMetadata() throws Exception {
        String clientId = generator.generate();
        jdbcTemplate.execute(
                String.format("insert into oauth_client_details(client_id, identity_zone_id, created_by) values ('%s', '%s', '%s')",
                        clientId, IdentityZone.getUaaZoneId(), randomGUID)
        );
        ClientMetadata clientMetadata = createTestClientMetadata(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
        ClientMetadata createdClientMetadata = db.update(clientMetadata, IdentityZoneHolder.get().getId());

        ClientMetadata retrievedClientMetadata = db.retrieve(createdClientMetadata.getClientId(), IdentityZoneHolder.get().getId());

        assertThat(retrievedClientMetadata.getClientId(), is(clientMetadata.getClientId()));
        assertThat(retrievedClientMetadata.getIdentityZoneId(), is(IdentityZone.getUaaZoneId()));
        assertThat(retrievedClientMetadata.isShowOnHomePage(), is(clientMetadata.isShowOnHomePage()));
        assertThat(retrievedClientMetadata.getAppLaunchUrl(), is(clientMetadata.getAppLaunchUrl()));
        assertThat(retrievedClientMetadata.getAppIcon(), is(clientMetadata.getAppIcon()));
        assertThat(retrievedClientMetadata.getCreatedBy(), is(clientMetadata.getCreatedBy()));
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void retrieveClientMetadata_ThatDoesNotExist() {
        String clientId = generator.generate();
        db.retrieve(clientId, IdentityZoneHolder.get().getId());
    }

    @Test
    public void retrieveAllClientMetadata() throws Exception {
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaaZoneId() + "')");
        ClientMetadata clientMetadata1 = createTestClientMetadata(clientId, true, new URL("http://app.launch/url"), base64EncodedImg);
        db.update(clientMetadata1, IdentityZoneHolder.get().getId());
        String clientId2 = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId2 + "', '" + IdentityZone.getUaaZoneId() + "')");
        ClientMetadata clientMetadata2 = createTestClientMetadata(clientId2, true, new URL("http://app.launch/url"), base64EncodedImg);
        db.update(clientMetadata2, IdentityZoneHolder.get().getId());

        List<ClientMetadata> clientMetadatas = db.retrieveAll(IdentityZoneHolder.get().getId());


        assertThat(clientMetadatas, PredicateMatcher.has(m -> m.getClientId().equals(clientId)));
        assertThat(clientMetadatas, PredicateMatcher.has(m -> m.getClientId().equals(clientId2)));
    }

    @Test
    public void updateClientMetadata() throws Exception {
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZone.getUaaZoneId() + "')");
        ClientMetadata newClientMetadata = createTestClientMetadata(clientId, false, new URL("http://updated.app/launch/url"), base64EncodedImg);

        ClientMetadata updatedClientMetadata = db.update(newClientMetadata, IdentityZoneHolder.get().getId());

        assertThat(updatedClientMetadata.getClientId(), is(clientId));
        assertThat(updatedClientMetadata.getIdentityZoneId(), is(IdentityZone.getUaaZoneId()));
        assertThat(updatedClientMetadata.isShowOnHomePage(), is(newClientMetadata.isShowOnHomePage()));
        assertThat(updatedClientMetadata.getAppLaunchUrl(), is(newClientMetadata.getAppLaunchUrl()));
        assertThat(updatedClientMetadata.getAppIcon(), is(newClientMetadata.getAppIcon()));
    }

    @Test
    public void test_set_and_get_ClientName() {
        String clientId = generator.generate();
        jdbcTemplate.execute("insert into oauth_client_details(client_id, identity_zone_id) values ('" + clientId + "', '" + IdentityZoneHolder.get().getId() + "')");
        ClientMetadata data = createTestClientMetadata(clientId,
                false,
                null,
                null);
        data.setClientName(CLIENT_NAME);
        db.update(data, IdentityZoneHolder.get().getId());
        data = db.retrieve(clientId, IdentityZoneHolder.get().getId());
        assertEquals(CLIENT_NAME, data.getClientName());
    }

    private ClientMetadata createTestClientMetadata(String clientId, boolean showOnHomePage, URL appLaunchUrl, String appIcon) {
        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId(clientId);
        clientMetadata.setShowOnHomePage(showOnHomePage);
        clientMetadata.setAppLaunchUrl(appLaunchUrl);
        clientMetadata.setAppIcon(appIcon);
        clientMetadata.setCreatedBy(randomGUID);
        return clientMetadata;
    }

    private static final String base64EncodedImg = getResourceAsString(
            JdbcClientMetadataProvisioningTest.class,
            "base64EncodedImg");

}
