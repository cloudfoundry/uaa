package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WithDatabaseContext
class JdbcClientMetadataProvisioningTest {

    private static final String base64EncodedImg = getResourceAsString(
            JdbcClientMetadataProvisioningTest.class,
            "base64EncodedImg");

    private RandomValueStringGenerator randomValueStringGenerator;
    private String createdBy;
    private String identityZoneId;
    private String clientId;

    private JdbcClientMetadataProvisioning jdbcClientMetadataProvisioning;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void createDatasource() {
        randomValueStringGenerator = new RandomValueStringGenerator(8);
        createdBy = "createdBy-" + randomValueStringGenerator.generate();
        identityZoneId = "identityZoneId-" + randomValueStringGenerator.generate();
        clientId = "clientId-" + randomValueStringGenerator.generate();

        MultitenantJdbcClientDetailsService clientService = new MultitenantJdbcClientDetailsService(jdbcTemplate, null, passwordEncoder);
        jdbcClientMetadataProvisioning = new JdbcClientMetadataProvisioning(clientService, jdbcTemplate);
    }

    @Test
    void constraintViolation_WhenNoMatchingClientFound() throws Exception {
        ClientMetadata clientMetadata = createTestClientMetadata(
                randomValueStringGenerator.generate(),
                true,
                new URL("http://app.launch/url"),
                base64EncodedImg,
                createdBy);

        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcClientMetadataProvisioning.update(clientMetadata, identityZoneId));
    }

    @Test
    void createdByPadsTo36Chars() {
        jdbcTemplate.execute(insertIntoOauthClientDetails(clientId, identityZoneId, "abcdef"));

        ClientMetadata retrievedClientMetadata = jdbcClientMetadataProvisioning.retrieve(
                clientId,
                identityZoneId);

        assertThat(retrievedClientMetadata.getCreatedBy().length(), is(36));
    }

    @Test
    void retrieve() throws Exception {
        jdbcTemplate.execute(insertIntoOauthClientDetails(clientId, identityZoneId, createdBy));
        ClientMetadata clientMetadata = createTestClientMetadata(
                clientId,
                true,
                new URL("http://app.launch/url"),
                base64EncodedImg,
                createdBy);

        jdbcClientMetadataProvisioning.update(clientMetadata, identityZoneId);

        ClientMetadata retrievedClientMetadata = jdbcClientMetadataProvisioning.retrieve(clientId, identityZoneId);

        assertThat(retrievedClientMetadata.getClientId(), is(clientId));
        assertThat(retrievedClientMetadata.getIdentityZoneId(), is(identityZoneId));
        assertThat(retrievedClientMetadata.isShowOnHomePage(), is(true));
        assertThat(retrievedClientMetadata.getAppLaunchUrl(), is(new URL("http://app.launch/url")));
        assertThat(retrievedClientMetadata.getAppIcon(), is(base64EncodedImg));
        assertThat(retrievedClientMetadata.getCreatedBy(), containsString(createdBy));
    }

    @Test
    void retrieve_ThatDoesNotExist() {
        String clientId1 = randomValueStringGenerator.generate();
        String clientId2 = randomValueStringGenerator.generate();
        jdbcTemplate.execute(insertIntoOauthClientDetailsWithMetadata(clientId1, "zone1", "createdBy", "appLaunchUrl"));
        jdbcTemplate.execute(insertIntoOauthClientDetailsWithMetadata(clientId2, "zone2", "createdBy", "appLaunchUrl"));


        assertDoesNotThrow(
                () -> jdbcClientMetadataProvisioning.retrieve(clientId1, "zone1"));
        assertDoesNotThrow(
                () -> jdbcClientMetadataProvisioning.retrieve(clientId2, "zone2"));

        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcClientMetadataProvisioning.retrieve(clientId1, "zone2"));
        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcClientMetadataProvisioning.retrieve(clientId2, "zone1"));
    }

    @Test
    void retrieveAll() {
        String clientId1 = randomValueStringGenerator.generate();
        String clientId2 = randomValueStringGenerator.generate();
        String clientId3 = randomValueStringGenerator.generate();
        jdbcTemplate.execute(insertIntoOauthClientDetailsWithMetadata(clientId1, identityZoneId, "createdBy", "appLaunchUrl"));
        jdbcTemplate.execute(insertIntoOauthClientDetailsWithMetadata(clientId2, identityZoneId, "createdBy", "appLaunchUrl"));
        jdbcTemplate.execute(insertIntoOauthClientDetailsWithMetadata(clientId3, "other-zone", "createdBy", "appLaunchUrl"));

        List<String> clientIds = jdbcClientMetadataProvisioning
                .retrieveAll(identityZoneId)
                .stream()
                .map(ClientMetadata::getClientId)
                .collect(Collectors.toList());

        assertThat(clientIds, hasItem(clientId1));
        assertThat(clientIds, hasItem(clientId2));
        assertThat(clientIds, not(hasItem(clientId3)));
    }

    @Test
    void update() throws Exception {
        jdbcTemplate.execute(insertIntoOauthClientDetails(clientId, identityZoneId));
        ClientMetadata newClientMetadata = createTestClientMetadata(
                clientId,
                false,
                new URL("http://updated.app/launch/url"),
                base64EncodedImg,
                createdBy);

        ClientMetadata updatedClientMetadata = jdbcClientMetadataProvisioning.update(newClientMetadata, identityZoneId);

        assertThat(updatedClientMetadata.getClientId(), is(clientId));
        assertThat(updatedClientMetadata.getIdentityZoneId(), is(identityZoneId));
        assertThat(updatedClientMetadata.isShowOnHomePage(), is(newClientMetadata.isShowOnHomePage()));
        assertThat(updatedClientMetadata.getAppLaunchUrl(), is(newClientMetadata.getAppLaunchUrl()));
        assertThat(updatedClientMetadata.getAppIcon(), is(newClientMetadata.getAppIcon()));
    }

    @Test
    void setAndGetClientName() {
        jdbcTemplate.execute(insertIntoOauthClientDetails(clientId, identityZoneId));
        ClientMetadata data = createTestClientMetadata(
                clientId,
                false,
                null,
                null,
                createdBy);
        String clientName = "clientName" + randomValueStringGenerator.generate();
        data.setClientName(clientName);
        jdbcClientMetadataProvisioning.update(data, identityZoneId);
        data = jdbcClientMetadataProvisioning.retrieve(clientId, identityZoneId);
        assertEquals(clientName, data.getClientName());
    }

    private static ClientMetadata createTestClientMetadata(
            final String clientId,
            final boolean showOnHomePage,
            final URL appLaunchUrl,
            final String appIcon,
            final String createdBy) {
        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId(clientId);
        clientMetadata.setShowOnHomePage(showOnHomePage);
        clientMetadata.setAppLaunchUrl(appLaunchUrl);
        clientMetadata.setAppIcon(appIcon);
        clientMetadata.setCreatedBy(createdBy);
        return clientMetadata;
    }

    private static String insertIntoOauthClientDetails(
            final String clientId,
            final String identityZoneId
    ) {
        return String.format("insert into oauth_client_details(client_id, identity_zone_id) values ('%s', '%s')",
                clientId,
                identityZoneId);
    }

    private static String insertIntoOauthClientDetails(
            final String clientId,
            final String identityZoneId,
            final String createdBy
    ) {
        return String.format("insert into oauth_client_details(client_id, identity_zone_id, created_by) values ('%s', '%s', '%s')",
                clientId,
                identityZoneId,
                createdBy);
    }

    private static String insertIntoOauthClientDetailsWithMetadata(
            final String clientId,
            final String identityZoneId,
            final String createdBy,
            final String appLaunchUrl
    ) {
        return String.format("insert into oauth_client_details(client_id, identity_zone_id, created_by, app_launch_url) values ('%s', '%s', '%s', '%s')",
                clientId,
                identityZoneId,
                createdBy,
                appLaunchUrl);
    }

}
