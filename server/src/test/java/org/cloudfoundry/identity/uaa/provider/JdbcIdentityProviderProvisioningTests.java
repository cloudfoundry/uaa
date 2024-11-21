package org.cloudfoundry.identity.uaa.provider;

import static java.util.stream.Collectors.toSet;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.zone.IdentityZone.getUaaZoneId;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import org.apache.commons.collections4.SetUtils;
import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.springframework.util.StringUtils;

@WithDatabaseContext
class JdbcIdentityProviderProvisioningTests {

    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;
    private RandomValueStringGenerator generator;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private String origin;
    private String uaaZoneId;
    private String otherZoneId1;
    private String otherZoneId2;

    private static final Set<String> ALL_TYPES = Set.of(LDAP, OIDC10, UAA, OAUTH20, SAML, KEYSTONE, LOGIN_SERVER);

    @BeforeEach
    void createDatasource() {
        generator = new RandomValueStringGenerator();
        jdbcIdentityProviderProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        origin = "origin-" + generator.generate();
        uaaZoneId = getUaaZoneId();
        otherZoneId1 = "otherZoneId1-" + generator.generate();
        otherZoneId2 = "otherZoneId2-" + generator.generate();
    }

    @Test
    void deleteProvidersInZone() {
        //action - delete zone
        //should delete providers
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.getId()).thenReturn(otherZoneId1);
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        assertNotNull(createdIdp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{otherZoneId1}, Integer.class), is(1));
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(mockIdentityZone, null, otherZoneId1));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{otherZoneId1}, Integer.class), is(0));
    }

    @Test
    void deleteByIdentityZone_ShouldNotDeleteAliasIdentityProviders() {
        final String originSuffix = generator.generate();

        // IdP 1: created in custom zone, no alias
        final IdentityProvider idp1 = MultitenancyFixture.identityProvider("origin1-" + originSuffix, otherZoneId1);
        final IdentityProvider createdIdp1 = jdbcIdentityProviderProvisioning.create(idp1, otherZoneId1);
        Assertions.assertThat(createdIdp1).isNotNull();
        Assertions.assertThat(createdIdp1.getId()).isNotBlank();

        // IdP 2: created in custom zone, alias in UAA zone
        final String idp2Id = UUID.randomUUID().toString();
        final String idp2AliasId = UUID.randomUUID().toString();
        final String origin2 = "origin2-" + originSuffix;
        final IdentityProvider idp2 = MultitenancyFixture.identityProvider(origin2, otherZoneId1);
        idp2.setId(idp2Id);
        idp2.setAliasZid(uaaZoneId);
        idp2.setAliasId(idp2AliasId);
        final IdentityProvider createdIdp2 = jdbcIdentityProviderProvisioning.create(idp2, otherZoneId1);
        Assertions.assertThat(createdIdp2).isNotNull();
        Assertions.assertThat(createdIdp2.getId()).isNotBlank();
        final IdentityProvider idp2Alias = MultitenancyFixture.identityProvider(origin2, uaaZoneId);
        idp2Alias.setId(idp2AliasId);
        idp2Alias.setAliasZid(otherZoneId1);
        idp2Alias.setAliasId(idp2Id);
        final IdentityProvider createdIdp2Alias = jdbcIdentityProviderProvisioning.create(idp2Alias, uaaZoneId);
        Assertions.assertThat(createdIdp2Alias).isNotNull();
        Assertions.assertThat(createdIdp2Alias.getId()).isNotBlank();

        // check if all three entries are present in the DB
        assertIdentityProviderExists(createdIdp1.getId(), otherZoneId1);
        assertIdentityProviderExists(createdIdp2.getId(), otherZoneId1);
        assertIdentityProviderExists(createdIdp2Alias.getId(), uaaZoneId);

        // delete by zone
        final int rowsDeleted = jdbcIdentityProviderProvisioning.deleteByIdentityZone(otherZoneId1);

        // number should not include the alias IdP
        Assertions.assertThat(rowsDeleted).isEqualTo(2);

        // the two IdPs in the custom zone should be deleted, the alias should still be present
        assertIdentityProviderDoesNotExist(createdIdp1.getId(), otherZoneId1);
        assertIdentityProviderDoesNotExist(createdIdp2.getId(), otherZoneId1);
        assertIdentityProviderExists(createdIdp2Alias.getId(), uaaZoneId);
    }

    private void assertIdentityProviderExists(final String id, final String zoneId) {
        Assertions.assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=? and id=?", new Object[]{zoneId, id}, Integer.class)).isEqualTo(1);
    }

    private void assertIdentityProviderDoesNotExist(final String id, final String zoneId) {
        Assertions.assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=? and id=?", new Object[]{zoneId, id}, Integer.class)).isZero();
    }

    @Test
    void deleteProvidersInUaaZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        assertNotNull(createdIdp);
        int count = jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{uaaZoneId}, Integer.class);
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(createdIdp, null, uaaZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{uaaZoneId}, Integer.class), is(count - 1));
    }

    @Test
    void cannotDeleteUaaProviders() {
        //action try to delete uaa provider
        //should not do anything
        int count = jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{getUaaZoneId()}, Integer.class);
        IdentityProvider uaa = jdbcIdentityProviderProvisioning.retrieveByOrigin(UAA, getUaaZoneId());
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(uaa, null, getUaaZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{getUaaZoneId()}, Integer.class), is(count));
    }

    @Test
    void createAndUpdateIdentityProviderInDefaultZone() {
        IdentityProvider<UaaIdentityProviderDefinition> idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        String providerDescription = "Test Description";
        idp.setConfig(new UaaIdentityProviderDefinition(null, null));
        idp.getConfig().setProviderDescription(providerDescription);
        idp.setType(UAA);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        Map<String, Object> rawCreatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", createdIdp.getId());

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(idp.getOriginKey(), createdIdp.getOriginKey());
        assertEquals(idp.getType(), createdIdp.getType());
        assertEquals(idp.getConfig(), createdIdp.getConfig());
        assertEquals(providerDescription, createdIdp.getConfig().getProviderDescription());

        assertEquals(idp.getName(), rawCreatedIdp.get("name"));
        assertEquals(idp.getOriginKey(), rawCreatedIdp.get("origin_key"));
        assertEquals(idp.getType(), rawCreatedIdp.get("type"));
        assertEquals(idp.getConfig(), JsonUtils.readValue((String) rawCreatedIdp.get("config"), UaaIdentityProviderDefinition.class));
        assertEquals(uaaZoneId, rawCreatedIdp.get("identity_zone_id").toString().trim());

        idp.setId(createdIdp.getId());
        idp.setLastModified(new Timestamp(System.currentTimeMillis()));
        idp.setName("updated name");
        idp.setCreated(createdIdp.getCreated());
        idp.setConfig(new UaaIdentityProviderDefinition());
        idp.setOriginKey("new origin key");
        idp.setType(UAA);
        idp.setIdentityZoneId("somerandomID");
        createdIdp = jdbcIdentityProviderProvisioning.update(idp, uaaZoneId);

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(rawCreatedIdp.get("origin_key"), createdIdp.getOriginKey());
        assertEquals(UAA, createdIdp.getType()); //we don't allow other types anymore
        assertEquals(idp.getConfig(), createdIdp.getConfig());
        assertTrue(Math.abs(idp.getLastModified().getTime() - createdIdp.getLastModified().getTime()) < 1001);
        assertEquals(Integer.valueOf(rawCreatedIdp.get("version").toString()) + 1, createdIdp.getVersion());
        assertEquals(uaaZoneId, createdIdp.getIdentityZoneId());
    }

    @Test
    void retrieveOidcIdentityProviderWithoutExternalId() {
        String issuerURI = "https://oidc.issuer.domain.org";
        IdentityProvider<OIDCIdentityProviderDefinition> idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        String providerDescription = "Test Description";
        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = new OIDCIdentityProviderDefinition();
        oidcIdentityProviderDefinition.setIssuer(issuerURI);
        idp.setConfig(oidcIdentityProviderDefinition);
        idp.getConfig().setProviderDescription(providerDescription);
        idp.setType(OIDC10);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        // remove external_key to simulate existing IdP entry
        jdbcTemplate.update("update identity_provider set external_key='' where id = '" + createdIdp.getId() + "';");
        IdentityProvider readAgain = jdbcIdentityProviderProvisioning.retrieve(createdIdp.getId(), uaaZoneId);
        assertEquals(idp.getName(), readAgain.getName());
        assertEquals(idp.getOriginKey(), readAgain.getOriginKey());
        assertEquals(idp.getType(), readAgain.getType());
        assertEquals(providerDescription, readAgain.getConfig().getProviderDescription());
        OIDCIdentityProviderDefinition readAgainConfig = (OIDCIdentityProviderDefinition) readAgain.getConfig();
        assertEquals(issuerURI, readAgainConfig.getIssuer());
        // update
        oidcIdentityProviderDefinition.setIssuer("https://new");
        idp.setId(readAgain.getId());
        idp.setLastModified(new Timestamp(System.currentTimeMillis()));
        idp.setConfig(oidcIdentityProviderDefinition);
        IdentityProvider updateIdp = jdbcIdentityProviderProvisioning.update(idp, uaaZoneId);
        readAgainConfig = (OIDCIdentityProviderDefinition) updateIdp.getConfig();
        assertEquals("https://new", readAgainConfig.getIssuer());
    }

    @Test
    void retrieveOAuth2IdentityProviderWithoutExternalId() {
        String issuerURI = "https://oauth2.issuer.domain.org";
        IdentityProvider<RawExternalOAuthIdentityProviderDefinition> idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        String providerDescription = "Test Description";
        RawExternalOAuthIdentityProviderDefinition rawExternalOAuthIdentityProviderDefinition = new RawExternalOAuthIdentityProviderDefinition();
        rawExternalOAuthIdentityProviderDefinition.setIssuer(issuerURI);
        idp.setConfig(rawExternalOAuthIdentityProviderDefinition);
        idp.getConfig().setProviderDescription(providerDescription);
        idp.setType(OAUTH20);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        // remove external_key to simulate existing IdP entry
        jdbcTemplate.update("update identity_provider set external_key='' where id = '" + createdIdp.getId() + "';");
        IdentityProvider readAgain = jdbcIdentityProviderProvisioning.retrieve(createdIdp.getId(), uaaZoneId);
        assertEquals(idp.getName(), readAgain.getName());
        assertEquals(idp.getOriginKey(), readAgain.getOriginKey());
        assertEquals(idp.getType(), readAgain.getType());
        assertEquals(providerDescription, readAgain.getConfig().getProviderDescription());
        RawExternalOAuthIdentityProviderDefinition readAgainConfig = (RawExternalOAuthIdentityProviderDefinition) readAgain.getConfig();
        assertEquals(issuerURI, readAgainConfig.getIssuer());
    }

    @Test
    void retrieveSamlIdentityProviderWithoutExternalId() {
        String entityId = "https://entity.samlworld.domain.org";
        IdentityProvider<SamlIdentityProviderDefinition> idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        String providerDescription = "Test Description";
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = new SamlIdentityProviderDefinition();
        samlIdentityProviderDefinition.setIdpEntityId(entityId);
        idp.setConfig(samlIdentityProviderDefinition);
        idp.getConfig().setProviderDescription(providerDescription);
        idp.setType(SAML);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        SamlIdentityProviderDefinition readAgainConfig = (SamlIdentityProviderDefinition) createdIdp.getConfig();
        assertEquals(entityId, readAgainConfig.getIdpEntityId());
        // remove external_key to simulate existing IdP entry
        jdbcTemplate.update("update identity_provider set external_key='' where id = '" + createdIdp.getId() + "';");
        IdentityProvider readAgain = jdbcIdentityProviderProvisioning.retrieve(createdIdp.getId(), uaaZoneId);
        assertEquals(idp.getName(), readAgain.getName());
        assertEquals(idp.getOriginKey(), readAgain.getOriginKey());
        assertEquals(idp.getType(), readAgain.getType());
        assertEquals(providerDescription, readAgain.getConfig().getProviderDescription());
        readAgainConfig = (SamlIdentityProviderDefinition) readAgain.getConfig();
        assertNull(readAgainConfig.getIdpEntityId());
    }

    @Test
    void createIdentityProviderInOtherZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);

        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        Map<String, Object> rawCreatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", createdIdp.getId());

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(idp.getOriginKey(), createdIdp.getOriginKey());
        assertEquals(idp.getType(), createdIdp.getType());
        assertEquals(idp.getConfig(), createdIdp.getConfig());

        assertEquals(idp.getName(), rawCreatedIdp.get("name"));
        assertEquals(idp.getOriginKey(), rawCreatedIdp.get("origin_key"));
        assertEquals(idp.getType(), rawCreatedIdp.get("type"));
        assertEquals(idp.getConfig(), JsonUtils.readValue((String) rawCreatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(otherZoneId1, rawCreatedIdp.get("identity_zone_id"));
    }

    @Test
    void createIdentityProviderWithNonUniqueOriginKeyInDefaultZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        assertThrows(IdpAlreadyExistsException.class, () -> jdbcIdentityProviderProvisioning.create(idp, uaaZoneId));
    }

    @Test
    void createIdentityProviderWithNonUniqueOriginKeyInOtherZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        assertThrows(IdpAlreadyExistsException.class, () -> jdbcIdentityProviderProvisioning.create(idp, otherZoneId1));
    }

    @Test
    void createIdentityProvidersWithSameOriginKeyInBothZones() {
        IdentityProvider uaaIdp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(uaaIdp, uaaZoneId);

        String otherZoneId = "otherZoneId-" + generator.generate();
        IdentityProvider otherIdp = MultitenancyFixture.identityProvider(origin, otherZoneId);
        jdbcIdentityProviderProvisioning.create(otherIdp, otherZoneId);
    }

    @Test
    void updateIdentityProviderInDefaultZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        idp.setId(idpId);
        idp.setType(LDAP);
        idp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);

        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        idp.setConfig(definition);
        IdentityProvider updatedIdp = jdbcIdentityProviderProvisioning.update(idp, uaaZoneId);

        Map<String, Object> rawUpdatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", updatedIdp.getId());

        assertEquals(definition, updatedIdp.getConfig());
        assertEquals(definition, JsonUtils.readValue((String) rawUpdatedIdp.get("config"), LdapIdentityProviderDefinition.class));
        assertEquals(getUaaZoneId(), rawUpdatedIdp.get("identity_zone_id"));
    }

    @Test
    void updateIdentityProviderInOtherZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);

        AbstractIdentityProviderDefinition definition = new AbstractIdentityProviderDefinition();
        idp.setConfig(definition);
        IdentityProvider updatedIdp = jdbcIdentityProviderProvisioning.update(idp, otherZoneId1);

        Map<String, Object> rawUpdatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", updatedIdp.getId());

        assertEquals(definition, updatedIdp.getConfig());
        assertEquals(definition, JsonUtils.readValue((String) rawUpdatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(otherZoneId1, rawUpdatedIdp.get("identity_zone_id"));
    }

    @Test
    void retrieveIdentityProviderById() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        IdentityProvider retrievedIdp = jdbcIdentityProviderProvisioning.retrieve(idp.getId(), otherZoneId1);
        assertEquals(idp.getId(), retrievedIdp.getId());
        assertEquals(idp.getConfig(), retrievedIdp.getConfig());
        assertEquals(idp.getName(), retrievedIdp.getName());
        assertEquals(idp.getOriginKey(), retrievedIdp.getOriginKey());
    }

    @Test
    void retrieveAll() {
        List<IdentityProvider> identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(uaaZoneId);
        int numberOfIdps = identityProviders.size();

        IdentityProvider defaultZoneIdp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(defaultZoneIdp, uaaZoneId);
        identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(uaaZoneId);
        assertEquals(numberOfIdps + 1, identityProviders.size());

        String otherOrigin = "otherOrigin-" + generator.generate();
        String otherZoneId = "otherZoneId-" + generator.generate();
        IdentityProvider otherZoneIdp = MultitenancyFixture.identityProvider(otherOrigin, otherZoneId);
        jdbcIdentityProviderProvisioning.create(otherZoneIdp, otherZoneId);

        identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(otherZoneId);
        assertEquals(1, identityProviders.size());
    }

    @Test
    void retrieveIdentityProviderByOriginInSameZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);

        IdentityProvider retrievedIdp = jdbcIdentityProviderProvisioning.retrieveByOrigin(idp.getOriginKey(), otherZoneId1);
        assertEquals(idp.getId(), retrievedIdp.getId());
        assertEquals(idp.getConfig(), retrievedIdp.getConfig());
        assertEquals(idp.getName(), retrievedIdp.getName());
        assertEquals(idp.getOriginKey(), retrievedIdp.getOriginKey());
    }

    @Test
    void retrieveIdentityProviderByOriginInDifferentZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        IdentityProvider idp1 = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        assertThrows(EmptyResultDataAccessException.class, () -> jdbcIdentityProviderProvisioning.retrieveByOrigin(idp1.getOriginKey(), otherZoneId2));
    }

    @ParameterizedTest
    @MethodSource
    void retrieveActiveByTypes(final String[] types) {
        final Set<String> expectedTypes = new HashSet<>(Arrays.asList(types)); // eliminate duplicates

        // create one IdP for every expected type in the correct zone
        final List<String> expectedIdpIds = expectedTypes.stream()
                .map(type -> createIdp(type, "origin-" + generator.generate(), otherZoneId1))
                .toList();

        // have another type -> should not be in the result
        final Set<String> otherTypes = SetUtils.difference(ALL_TYPES, expectedTypes);
        for (final String otherType : otherTypes) {
            createIdp(otherType, "origin-" + generator.generate(), otherZoneId1);
        }

        // have the correct type, but another zone -> should not be in the result
        for (final String type : expectedTypes) {
            createIdp(type, "origin-" + generator.generate(), otherZoneId2);
        }

        final List<IdentityProvider> result = jdbcIdentityProviderProvisioning.retrieveActiveByTypes(otherZoneId1,
                types);
        final Set<String> idsInResult = result.stream().map(IdentityProvider::getId).collect(toSet());
        assertEquals(expectedIdpIds.size(), idsInResult.size());
        for (final String id : expectedIdpIds) {
            assertTrue(idsInResult.contains(id));
        }
    }

    private static Stream<Arguments> retrieveActiveByTypes() {
        return Stream.of(
                new String[] { },
                new String[] { OAUTH20, OIDC10 },
                new String[] { OAUTH20, OIDC10, SAML },
                new String[] { SAML },
                new String[] { OIDC10 },
                new String[] { LDAP, UAA, OAUTH20, OIDC10 },
                new String[] { LDAP, UAA, OAUTH20, LDAP, LDAP, OIDC10 }, // contains duplicates
                (Object) new String[] { LDAP, UAA, OAUTH20, OIDC10, OIDC10, UAA } // contains duplicates
        ).map(Arguments::of);
    }

    private String createIdp(final String type, final String originKey, final String zoneId) {
        final String idpId = "idpId-" + generator.generate();
        final IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, idpId);
        idp.setId(idpId);
        idp.setType(type);
        final IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, zoneId);
        final String idpIdCreated = createdIdp.getId();
        assertTrue(StringUtils.hasText(idpIdCreated));
        return idpIdCreated;
    }

    @Test
    void testIdpWithAliasExistsInZone_TrueCase() {
        final IdentityProvider<AbstractIdentityProviderDefinition> idpWithAlias = MultitenancyFixture.identityProvider(
                generator.generate(),
                otherZoneId1
        );
        idpWithAlias.setAliasZid(IdentityZone.getUaaZoneId());
        idpWithAlias.setAliasId(UUID.randomUUID().toString());
        jdbcIdentityProviderProvisioning.create(idpWithAlias, otherZoneId1);
        assertTrue(jdbcIdentityProviderProvisioning.idpWithAliasExistsInZone(otherZoneId1));
    }

    @Test
    void testIdpWithAliasExistsInZone_FalseCase() {
        final IdentityProvider<AbstractIdentityProviderDefinition> idp = MultitenancyFixture.identityProvider(
                generator.generate(),
                otherZoneId2
        );
        jdbcIdentityProviderProvisioning.create(idp, otherZoneId2);
        assertFalse(jdbcIdentityProviderProvisioning.idpWithAliasExistsInZone(otherZoneId2));
    }
}
