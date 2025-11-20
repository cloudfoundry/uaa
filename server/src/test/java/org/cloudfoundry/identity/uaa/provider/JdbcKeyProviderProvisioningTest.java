package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.KeyProviderAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.KeyProviderNotFoundException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

@WithDatabaseContext
public class JdbcKeyProviderProvisioningTest {
    JdbcKeyProviderProvisioning provisioning;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public static final String GET_KEY_PROVIDER_BY_ID_SQL = "select * from key_provider_config where id=?";
    public static final String GET_KEY_PROVIDER_BY_ZONE_ID_SQL = "select * from key_provider_config where identity_zone_id=?";

    @BeforeEach
    public void setup() {
        provisioning = new JdbcKeyProviderProvisioning(jdbcTemplate);
    }

    @Test
    public void testCreate() {
        String identityZoneId = new RandomValueStringGenerator(5).generate();
        String currentZoneId = IdentityZoneHolder.get().getId();
        IdentityZoneHolder.get().setId(identityZoneId);
        KeyProviderConfig keyProviderConfig = new KeyProviderConfig("client1", "tenant1");
        KeyProviderConfig created = provisioning.create(keyProviderConfig);

        assertEquals("client1", created.getClientId());
        assertEquals("tenant1", created.getDcsTenantId());
        List<KeyProviderConfig> results = jdbcTemplate.query(GET_KEY_PROVIDER_BY_ID_SQL, JdbcKeyProviderProvisioning.mapper, created.getId());
        assertEquals(1, results.size());
        assertEquals(created, results.get(0));
        IdentityZoneHolder.get().setId(currentZoneId);
    }

    @Test
    public void testCreateForExistingZone() {
        String identityZoneId = new RandomValueStringGenerator(5).generate();
        String currentZoneId = IdentityZoneHolder.get().getId();
        IdentityZoneHolder.get().setId(identityZoneId);
        KeyProviderConfig keyProviderConfig = new KeyProviderConfig("client1", "tenant1");
        provisioning.create(keyProviderConfig);

        Throwable exception = Assertions.assertThrows(KeyProviderAlreadyExistsException.class, () -> {
            provisioning.create(keyProviderConfig);
        });
        assertEquals("Key provider already exists for this zone.", exception.getMessage());
        IdentityZoneHolder.get().setId(currentZoneId);
    }

    @Test
    public void testRetrieve() {
        String identityZoneId = new RandomValueStringGenerator(5).generate();
        String currentZoneId = IdentityZoneHolder.get().getId();
        IdentityZoneHolder.get().setId(identityZoneId);
        String keyProviderId = createKeyProvider();
        KeyProviderConfig keyProviderConfig = provisioning.retrieve(keyProviderId);
        assertEquals("client1", keyProviderConfig.getClientId());
        assertEquals("tenant1", keyProviderConfig.getDcsTenantId());
        IdentityZoneHolder.get().setId(currentZoneId);
    }

    private String createKeyProvider() {
        String keyProviderId = UUID.randomUUID().toString();
        jdbcTemplate.update(JdbcKeyProviderProvisioning.INSERT_KEY_PROVIDER_CONFIG, keyProviderId, IdentityZoneHolder.get().getId(), "client1", "tenant1");
        return keyProviderId;
    }

    @Test
    public void testDelete() {
        String identityZoneId = new RandomValueStringGenerator(5).generate();
        String currentZoneId = IdentityZoneHolder.get().getId();
        IdentityZoneHolder.get().setId(identityZoneId);
        String keyProviderId = createKeyProvider();
        KeyProviderConfig keyProviderConfig = provisioning.retrieve(keyProviderId);
        assertEquals("client1", keyProviderConfig.getClientId());
        assertEquals("tenant1", keyProviderConfig.getDcsTenantId());

        assertEquals(1, provisioning.delete(keyProviderId));

        Assertions.assertThrows(KeyProviderNotFoundException.class, () -> {
            provisioning.retrieve(keyProviderId);
        });
        IdentityZoneHolder.get().setId(currentZoneId);
    }

    @Test
    public void testDeleteNotFound() {
        assertEquals(0, provisioning.delete("INVALID_ID"));
    }

    @Test
    public void testFindActiveForZone() {
        String identityZoneId = new RandomValueStringGenerator(5).generate();
        String currentZoneId = IdentityZoneHolder.get().getId();
        IdentityZoneHolder.get().setId(identityZoneId);
        String keyProviderId = createKeyProvider();
        assertEquals(keyProviderId, provisioning.findActive().getId());
        IdentityZoneHolder.get().setId(currentZoneId);
    }

    @Test
    public void testFindActiveForZoneZeroResults() {
        assertNull(provisioning.findActive());
    }

    @Test
    public void testDeleteByZoneId() {
        String keyProviderId1 = UUID.randomUUID().toString();
        String identityZoneId = new RandomValueStringGenerator(5).generate();
        String zoneId1 = identityZoneId + "1";
        jdbcTemplate.update(JdbcKeyProviderProvisioning.INSERT_KEY_PROVIDER_CONFIG, keyProviderId1, zoneId1, "client1", "tenant1");
        String keyProviderId2 = UUID.randomUUID().toString();
        assertEquals(1, jdbcTemplate.query(GET_KEY_PROVIDER_BY_ZONE_ID_SQL, JdbcKeyProviderProvisioning.mapper, zoneId1).size());
        String zoneId2 = identityZoneId + "2";
        jdbcTemplate.update(JdbcKeyProviderProvisioning.INSERT_KEY_PROVIDER_CONFIG, keyProviderId2, zoneId2, "client1", "tenant1");

        String currentZoneId = IdentityZoneHolder.get().getId();
        IdentityZoneHolder.get().setId(zoneId1);
        assertEquals(1, provisioning.deleteByIdentityZone(zoneId1));

        assertEquals(0, jdbcTemplate.query(GET_KEY_PROVIDER_BY_ZONE_ID_SQL, JdbcKeyProviderProvisioning.mapper, zoneId1).size());
        assertEquals(1, jdbcTemplate.query(GET_KEY_PROVIDER_BY_ZONE_ID_SQL, JdbcKeyProviderProvisioning.mapper, zoneId2).size());

        IdentityZoneHolder.get().setId(currentZoneId);
    }

}