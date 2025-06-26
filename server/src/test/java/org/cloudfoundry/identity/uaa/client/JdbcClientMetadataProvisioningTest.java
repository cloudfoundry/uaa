package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.extensions.profiles.DisabledIfProfile;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.URI;
import java.net.URL;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

@WithDatabaseContext
class JdbcClientMetadataProvisioningTest {

    private static final String base64EncodedImg = getResourceAsString(
            JdbcClientMetadataProvisioningTest.class,
            "base64EncodedImg");

    private AlphanumericRandomValueStringGenerator randomValueStringGenerator;
    private String createdBy;
    private String identityZoneId;
    private String clientId;

    private JdbcClientMetadataProvisioning jdbcClientMetadataProvisioning;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void createDatasource() {
        randomValueStringGenerator = new AlphanumericRandomValueStringGenerator(8);
        createdBy = "createdBy-" + randomValueStringGenerator.generate();
        identityZoneId = "identityZoneId-" + randomValueStringGenerator.generate();
        clientId = "clientId-" + randomValueStringGenerator.generate();

        MultitenantJdbcClientDetailsService clientService = new MultitenantJdbcClientDetailsService(namedJdbcTemplate, null, passwordEncoder);
        jdbcClientMetadataProvisioning = new JdbcClientMetadataProvisioning(clientService, jdbcTemplate);
    }

    @Test
    void constraintViolation_WhenNoMatchingClientFound() throws Exception {
        ClientMetadata clientMetadata = createTestClientMetadata(
                randomValueStringGenerator.generate(),
                true,
                URI.create("http://app.launch/url").toURL(),
                base64EncodedImg,
                createdBy);

        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcClientMetadataProvisioning.update(clientMetadata, identityZoneId));
    }

    /**
     * In MySQL, characters are stored with a padding, but when they are retrieved, the padding is trimmed.
     * To disable this behavior, you must add the {@code sql_mode} to include {@code PAD_CHAR_TO_FULL_LENGTH}.
     *
     * @see <a href="https://dev.mysql.com/doc/refman/8.4/en/char.html">CHAR type docs</a>
     * @see <a href="https://dev.mysql.com/doc/refman/8.4/en/sql-mode.html#sqlmode_pad_char_to_full_length"> PAD_CHAR_TO_FULL_LENGTH </a>
     */
    @Test
    @DisabledIfProfile("mysql")
    void createdByPadsTo36Chars() {
        jdbcTemplate.execute(insertIntoOauthClientDetails(clientId, identityZoneId, "abcdef"));

        ClientMetadata retrievedClientMetadata = jdbcClientMetadataProvisioning.retrieve(
                clientId,
                identityZoneId);

        assertThat(retrievedClientMetadata.getCreatedBy()).hasSize(36);
    }

    @Test
    void retrieve() throws Exception {
        jdbcTemplate.execute(insertIntoOauthClientDetails(clientId, identityZoneId, createdBy));
        ClientMetadata clientMetadata = createTestClientMetadata(
                clientId,
                true,
                URI.create("http://app.launch/url").toURL(),
                base64EncodedImg,
                createdBy);

        jdbcClientMetadataProvisioning.update(clientMetadata, identityZoneId);

        ClientMetadata retrievedClientMetadata = jdbcClientMetadataProvisioning.retrieve(clientId, identityZoneId);

        assertThat(retrievedClientMetadata.getClientId()).isEqualTo(clientId);
        assertThat(retrievedClientMetadata.getIdentityZoneId()).isEqualTo(identityZoneId);
        assertThat(retrievedClientMetadata.isShowOnHomePage()).isTrue();
        assertThat(retrievedClientMetadata.getAppLaunchUrl()).isEqualTo(URI.create("http://app.launch/url").toURL());
        assertThat(retrievedClientMetadata.getAppIcon()).isEqualTo(base64EncodedImg);
        assertThat(retrievedClientMetadata.getCreatedBy()).contains(createdBy);
    }

    @Test
    void retrieve_ThatDoesNotExist() {
        String clientId1 = randomValueStringGenerator.generate();
        String clientId2 = randomValueStringGenerator.generate();
        jdbcTemplate.execute(insertIntoOauthClientDetailsWithMetadata(clientId1, "zone1", "createdBy", "appLaunchUrl"));
        jdbcTemplate.execute(insertIntoOauthClientDetailsWithMetadata(clientId2, "zone2", "createdBy", "appLaunchUrl"));

        assertThatNoException().isThrownBy(
                () -> jdbcClientMetadataProvisioning.retrieve(clientId1, "zone1"));
        assertThatNoException().isThrownBy(
                () -> jdbcClientMetadataProvisioning.retrieve(clientId2, "zone2"));

        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcClientMetadataProvisioning.retrieve(clientId1, "zone2"));
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcClientMetadataProvisioning.retrieve(clientId2, "zone1"));
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
                .toList();

        assertThat(clientIds).contains(clientId1, clientId2)
                .doesNotContain(clientId3);
    }

    @Test
    void update() throws Exception {
        jdbcTemplate.execute(insertIntoOauthClientDetails(clientId, identityZoneId));
        ClientMetadata newClientMetadata = createTestClientMetadata(
                clientId,
                false,
                URI.create("http://updated.app/launch/url").toURL(),
                base64EncodedImg,
                createdBy);

        ClientMetadata updatedClientMetadata = jdbcClientMetadataProvisioning.update(newClientMetadata, identityZoneId);

        assertThat(updatedClientMetadata.getClientId()).isEqualTo(clientId);
        assertThat(updatedClientMetadata.getIdentityZoneId()).isEqualTo(identityZoneId);
        assertThat(updatedClientMetadata.isShowOnHomePage()).isEqualTo(newClientMetadata.isShowOnHomePage());
        assertThat(updatedClientMetadata.getAppLaunchUrl()).isEqualTo(newClientMetadata.getAppLaunchUrl());
        assertThat(updatedClientMetadata.getAppIcon()).isEqualTo(newClientMetadata.getAppIcon());
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
        assertThat(data.getClientName()).isEqualTo(clientName);
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
        return "insert into oauth_client_details(client_id, identity_zone_id) values ('%s', '%s')".formatted(
                clientId,
                identityZoneId);
    }

    private static String insertIntoOauthClientDetails(
            final String clientId,
            final String identityZoneId,
            final String createdBy
    ) {
        return "insert into oauth_client_details(client_id, identity_zone_id, created_by) values ('%s', '%s', '%s')".formatted(
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
        return "insert into oauth_client_details(client_id, identity_zone_id, created_by, app_launch_url) values ('%s', '%s', '%s', '%s')".formatted(
                clientId,
                identityZoneId,
                createdBy,
                appLaunchUrl);
    }

}
