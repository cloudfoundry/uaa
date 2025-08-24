package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

@WithDatabaseContext
class JdbcIdentityZoneProvisioningTests {

    private JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;
    private RandomValueStringGenerator randomValueStringGenerator;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        jdbcIdentityZoneProvisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        randomValueStringGenerator = new RandomValueStringGenerator(8);
        jdbcTemplate.execute("delete from identity_zone where id != 'uaa'");
    }

    @Test
    void delete_zone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", Integer.class, new Object[]{createdIdZone.getId()})).isOne();
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(identityZone, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", Integer.class, new Object[]{createdIdZone.getId()})).isZero();
    }

    @Test
    void cannot_delete_uaa_zone() {
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", Integer.class, new Object[]{IdentityZone.getUaaZoneId()})).isOne();
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", Integer.class, new Object[]{IdentityZone.getUaaZoneId()})).isOne();
    }

    @Test
    void createIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(createdIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(createdIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(createdIdZone.getDescription()).isEqualTo(identityZone.getDescription());
        assertThat(createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(3600);
        assertThat(createdIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity()).isEqualTo(7200);
        assertThat(createdIdZone.isActive()).isTrue();
    }

    @Test
    void createIdentityZoneSubdomainBecomesLowerCase() {
        String subdomain = randomValueStringGenerator.generate().toUpperCase();
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), subdomain);
        identityZone.setId(randomValueStringGenerator.generate());

        identityZone.setSubdomain(subdomain);
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(createdIdZone.getSubdomain()).isEqualTo(subdomain.toLowerCase());
        assertThat(createdIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(createdIdZone.getDescription()).isEqualTo(identityZone.getDescription());
    }

    @Test
    void null_subdomain() {
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.retrieveBySubdomain(null));
    }

    @Test
    void updateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(createdIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(createdIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(createdIdZone.getDescription()).isEqualTo(identityZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain);
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertThat(updatedIdZone.getId()).isEqualTo(createdIdZone.getId());
        assertThat(updatedIdZone.getSubdomain()).isEqualTo(createdIdZone.getSubdomain().toLowerCase());
        assertThat(updatedIdZone.getName()).isEqualTo(createdIdZone.getName());
        assertThat(updatedIdZone.getDescription()).isEqualTo(createdIdZone.getDescription());
        assertThat(updatedIdZone.isActive()).isEqualTo(createdIdZone.isActive());
    }

    @Test
    void updateIdentityZoneSubDomainIsLowerCase() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(createdIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(createdIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(createdIdZone.getDescription()).isEqualTo(identityZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain.toUpperCase());
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertThat(updatedIdZone.getId()).isEqualTo(createdIdZone.getId());
        assertThat(updatedIdZone.getSubdomain()).isEqualTo(createdIdZone.getSubdomain().toLowerCase());
        assertThat(updatedIdZone.getName()).isEqualTo(createdIdZone.getName());
        assertThat(updatedIdZone.getDescription()).isEqualTo(createdIdZone.getDescription());
    }

    @Test
    void createIdentityZoneInactive() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.isActive()).isFalse();
    }

    @Test
    void updateIdentityZoneSetInactive() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.isActive()).isTrue();

        createdIdZone.setActive(false);
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertThat(updatedIdZone.isActive()).isFalse();
    }

    @Test
    void deleteInactiveIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        int deletedZones = jdbcIdentityZoneProvisioning.deleteByIdentityZone(createdIdZone.getId());

        assertThat(deletedZones).isOne();
    }

    @Test
    void updateNonExistentIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        assertThatExceptionOfType(ZoneDoesNotExistsException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.update(identityZone));
    }

    @Test
    void createDuplicateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one", "there-can-be-only-one");
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);
        try {
            jdbcIdentityZoneProvisioning.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

    @Test
    void createDuplicateIdentityZoneSubdomain() {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one", "there-can-be-only-one");
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);
        try {
            identityZone.setId(new RandomValueStringGenerator().generate());
            jdbcIdentityZoneProvisioning.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

    @Test
    void getIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertThat(retrievedIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(retrievedIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(retrievedIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(retrievedIdZone.getDescription()).isEqualTo(identityZone.getDescription());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertThat(retrievedIdZone.isActive()).isTrue();
    }

    @Test
    void getAllIdentityZones() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        List<IdentityZone> identityZones = jdbcIdentityZoneProvisioning.retrieveAll();

        assertThat(identityZones)
                .hasSize(2)
                .contains(identityZone);
    }

    @Test
    void getIdentityZoneBySubdomain() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieveBySubdomain(identityZone.getSubdomain());

        assertThat(retrievedIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(retrievedIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(retrievedIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(retrievedIdZone.getDescription()).isEqualTo(identityZone.getDescription());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertThat(retrievedIdZone.isActive()).isTrue();
    }

    @Test
    void getInactiveIdentityZoneFails() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        try {
            jdbcIdentityZoneProvisioning.retrieve(createdIdZone.getId());
            fail("Able to retrieve inactive zone.");
        } catch (ZoneDoesNotExistsException e) {
            assertThat(e.getMessage()).contains(createdIdZone.getId());
        }
    }

    @Test
    void getInactiveIdentityZoneIgnoringActiveFlag() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieveIgnoreActiveFlag(createdIdZone.getId());

        assertThat(retrievedIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(retrievedIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(retrievedIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(retrievedIdZone.getDescription()).isEqualTo(identityZone.getDescription());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertThat(retrievedIdZone.isActive()).isFalse();
    }

    @Test
    void identityZoneRetrieveZoneIdNull() {
        assertThatExceptionOfType(ZoneDoesNotExistsException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.retrieve(null));
        assertThatExceptionOfType(ZoneDoesNotExistsException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.retrieveIgnoreActiveFlag(null));
    }

    @Test
    void identityZoneUpdateSubDomainSame() {
        String subDomain = randomValueStringGenerator.generate();
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), subDomain);
        identityZone.setConfig(null);
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        IdentityZone createdIdZone2 = jdbcIdentityZoneProvisioning.create(identityZone2);

        assertThat(createdIdZone2.getSubdomain()).isNotEqualTo(createdIdZone.getSubdomain());
        createdIdZone2.setConfig(null);
        createdIdZone2.setSubdomain(subDomain);
        assertThatExceptionOfType(ZoneAlreadyExistsException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.update(createdIdZone2));
    }

    @Test
    void createIdentityZoneInvalidZoneConfigResetConfigIntialValues() {
        String zoneId = randomValueStringGenerator.generate();
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        assertThat(createdIdZone).isNotNull();
        assertThat(createdIdZone.getConfig()).isNotNull();
        assertThat(createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(3600);
        // corrupt the config entry
        jdbcTemplate.update("update identity_zone set config=? where id=?", "invalid", identityZone.getId());
        // retrieve zone again
        createdIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());
        assertThat(createdIdZone).isNotNull();
        assertThat(createdIdZone.getConfig()).isNotNull();
        assertThat(createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(-1);
    }
}
