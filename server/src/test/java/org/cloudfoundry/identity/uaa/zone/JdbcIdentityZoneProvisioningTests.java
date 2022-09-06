package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

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
    void test_delete_zone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{createdIdZone.getId()}, Integer.class), is(1));
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(identityZone, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{createdIdZone.getId()}, Integer.class), is(0));
    }

    @Test
    void test_cannot_delete_uaa_zone() {
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{IdentityZone.getUaaZoneId()}, Integer.class), is(1));
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{IdentityZone.getUaaZoneId()}, Integer.class), is(1));
    }

    @Test
    void testCreateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertEquals(3600, createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(7200, createdIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(createdIdZone.isActive());

        assertFalse(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertNull(createdIdZone.getConfig().getLinks().getSelfService().getPasswd());
        assertNull(createdIdZone.getConfig().getLinks().getSelfService().getSignup());
    }

    @Test
    void testCreateIdentityZone_enabledLegacySelfService() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        identityZone.getConfig().getLinks().getSelfService().setSignup("");
        identityZone.getConfig().getLinks().getSelfService().setPasswd("/forgot_password");

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertFalse(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(createdIdZone.getConfig().getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertEquals(createdIdZone.getConfig().getLinks().getSelfService().getSignup(), "");
    }

    @Test
    void testCreateIdentityZone_enabledSelfServiceCreateAccount() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertTrue(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
    }

    @Test
    void testCreateIdentityZone_enabledSelfServiceResetPassword() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceResetPasswordEnabled(true);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertTrue(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
    }

    @Test
    void testCreateIdentityZone_disabledSelfServiceResetPassword() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceResetPasswordEnabled(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertFalse(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
    }

    @Test
    void testCreateIdentityZone_bothEnabledSelfServiceCreateAccountAndSelfServiceResetPassword() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertFalse(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
    }

    @Test
    void testCreateIdentityZone_Subdomain_Becomes_LowerCase() {
        String subdomain = randomValueStringGenerator.generate().toUpperCase();
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), subdomain);
        identityZone.setId(randomValueStringGenerator.generate());

        identityZone.setSubdomain(subdomain);
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(subdomain.toLowerCase(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
    }

    @Test
    void test_null_subdomain() {
        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcIdentityZoneProvisioning.retrieveBySubdomain(null));
    }

    @Test
    void testUpdateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain);
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertEquals(createdIdZone.getId(), updatedIdZone.getId());
        assertEquals(createdIdZone.getSubdomain().toLowerCase(), updatedIdZone.getSubdomain());
        assertEquals(createdIdZone.getName(), updatedIdZone.getName());
        assertEquals(createdIdZone.getDescription(), updatedIdZone.getDescription());
        assertEquals(createdIdZone.isActive(), updatedIdZone.isActive());
    }

    @Test
    void testUpdateIdentityZone_SubDomain_Is_LowerCase() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain.toUpperCase());
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertEquals(createdIdZone.getId(), updatedIdZone.getId());
        assertEquals(createdIdZone.getSubdomain().toLowerCase(), updatedIdZone.getSubdomain());
        assertEquals(createdIdZone.getName(), updatedIdZone.getName());
        assertEquals(createdIdZone.getDescription(), updatedIdZone.getDescription());
    }

    @Test
    void testCreateIdentityZoneInactive() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertFalse(createdIdZone.isActive());
    }

    @Test
    void testUpdateIdentityZoneSetInactive() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertTrue(createdIdZone.isActive());

        createdIdZone.setActive(false);
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertFalse(updatedIdZone.isActive());
    }

    @Test
    void testDeleteInactiveIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        int deletedZones = jdbcIdentityZoneProvisioning.deleteByIdentityZone(createdIdZone.getId());

        assertEquals(1, deletedZones);
    }

    @Test
    void testUpdateNonExistentIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        assertThrows(ZoneDoesNotExistsException.class,
                () -> jdbcIdentityZoneProvisioning.update(identityZone));
    }

    @Test
    void testCreateDuplicateIdentityZone() {
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
    void testCreateDuplicateIdentityZoneSubdomain() {
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
    void testGetIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        identityZone.getConfig().getLinks().getSelfService().setSignup(null);
        identityZone.getConfig().getLinks().getSelfService().setPasswd(null);
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());

        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertNull(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd());
        assertNull(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup());
    }

    @Test
    void testGetIdentityZone_disabledLegacySelfService() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        identityZone.getConfig().getLinks().getSelfService().setSignup(null);
        identityZone.getConfig().getLinks().getSelfService().setPasswd(null);
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());

        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertNull(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd());
        assertNull(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup());
    }

    @Test
    void testGetIdentityZone_enabledLegacySelfService() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        identityZone.getConfig().getLinks().getSelfService().setSignup("");
        identityZone.getConfig().getLinks().getSelfService().setPasswd("/forgot_password");
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());

        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup(), "");
    }

    @Test
    void testGetIdentityZone_enabledLegacySelfServiceAndLinks() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        identityZone.getConfig().getLinks().getSelfService().setSignup("/create_account");
        identityZone.getConfig().getLinks().getSelfService().setPasswd("/forgot_password");
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());

        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup(), "/create_account");
    }


    @Test
    void testGetIdentityZone_enabledLegacySelfServiceFlagAndPasswdLink() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        config.getLinks().getSelfService().setSignup("");
        config.getLinks().getSelfService().setPasswd("/forgot_password");
        identityZone.setConfig(config);

        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());

        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup(), "");
    }

    @Test
    void testGetAllIdentityZones() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        List<IdentityZone> identityZones = jdbcIdentityZoneProvisioning.retrieveAll();

        assertEquals(2, identityZones.size());
        assertTrue(identityZones.contains(identityZone));
    }

    @Test
    void testGetIdentityZoneBySubdomain() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieveBySubdomain(identityZone.getSubdomain());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());
    }

    @Test
    void testGetInactiveIdentityZoneFails() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        try {
            jdbcIdentityZoneProvisioning.retrieve(createdIdZone.getId());
            fail("Able to retrieve inactive zone.");
        } catch (ZoneDoesNotExistsException e) {
            assertThat(e.getMessage(), containsString(createdIdZone.getId()));
        }
    }

    @Test
    void testGetInactiveIdentityZoneIgnoringActiveFlag() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieveIgnoreActiveFlag(createdIdZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertFalse(retrievedIdZone.isActive());
    }

}
