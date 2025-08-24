package org.cloudfoundry.identity.uaa.provider;

import org.apache.commons.collections4.SetUtils;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
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
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.zone.IdentityZone.getUaaZoneId;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
        assertThat(createdIdp).isNotNull();
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", Integer.class, new Object[]{otherZoneId1})).isOne();
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(mockIdentityZone, null, otherZoneId1));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", Integer.class, new Object[]{otherZoneId1})).isZero();
    }

    @Test
    void deleteByIdentityZone_ShouldNotDeleteAliasIdentityProviders() {
        final String originSuffix = generator.generate();

        // IdP 1: created in custom zone, no alias
        final IdentityProvider idp1 = MultitenancyFixture.identityProvider("origin1-" + originSuffix, otherZoneId1);
        final IdentityProvider createdIdp1 = jdbcIdentityProviderProvisioning.create(idp1, otherZoneId1);
        assertThat(createdIdp1).isNotNull();
        assertThat(createdIdp1.getId()).isNotBlank();

        // IdP 2: created in custom zone, alias in UAA zone
        final String idp2Id = UUID.randomUUID().toString();
        final String idp2AliasId = UUID.randomUUID().toString();
        final String origin2 = "origin2-" + originSuffix;
        final IdentityProvider idp2 = MultitenancyFixture.identityProvider(origin2, otherZoneId1);
        idp2.setId(idp2Id);
        idp2.setAliasZid(uaaZoneId);
        idp2.setAliasId(idp2AliasId);
        final IdentityProvider createdIdp2 = jdbcIdentityProviderProvisioning.create(idp2, otherZoneId1);
        assertThat(createdIdp2).isNotNull();
        assertThat(createdIdp2.getId()).isNotBlank();
        final IdentityProvider idp2Alias = MultitenancyFixture.identityProvider(origin2, uaaZoneId);
        idp2Alias.setId(idp2AliasId);
        idp2Alias.setAliasZid(otherZoneId1);
        idp2Alias.setAliasId(idp2Id);
        final IdentityProvider createdIdp2Alias = jdbcIdentityProviderProvisioning.create(idp2Alias, uaaZoneId);
        assertThat(createdIdp2Alias).isNotNull();
        assertThat(createdIdp2Alias.getId()).isNotBlank();

        // check if all three entries are present in the DB
        assertIdentityProviderExists(createdIdp1.getId(), otherZoneId1);
        assertIdentityProviderExists(createdIdp2.getId(), otherZoneId1);
        assertIdentityProviderExists(createdIdp2Alias.getId(), uaaZoneId);

        // delete by zone
        final int rowsDeleted = jdbcIdentityProviderProvisioning.deleteByIdentityZone(otherZoneId1);

        // number should not include the alias IdP
        assertThat(rowsDeleted).isEqualTo(2);

        // the two IdPs in the custom zone should be deleted, the alias should still be present
        assertIdentityProviderDoesNotExist(createdIdp1.getId(), otherZoneId1);
        assertIdentityProviderDoesNotExist(createdIdp2.getId(), otherZoneId1);
        assertIdentityProviderExists(createdIdp2Alias.getId(), uaaZoneId);
    }

    private void assertIdentityProviderExists(final String id, final String zoneId) {
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=? and id=?", Integer.class, new Object[]{zoneId, id})).isOne();
    }

    private void assertIdentityProviderDoesNotExist(final String id, final String zoneId) {
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=? and id=?", Integer.class, new Object[]{zoneId, id})).isZero();
    }

    @Test
    void deleteProvidersInUaaZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        assertThat(createdIdp).isNotNull();
        int count = jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", Integer.class, new Object[]{uaaZoneId});
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(createdIdp, null, uaaZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", Integer.class, new Object[]{uaaZoneId})).isEqualTo(count - 1);
    }

    @Test
    void cannotDeleteUaaProviders() {
        //action try to delete uaa provider
        //should not do anything
        int count = jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", Integer.class, new Object[]{getUaaZoneId()});
        IdentityProvider uaa = jdbcIdentityProviderProvisioning.retrieveByOrigin(UAA, getUaaZoneId());
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(uaa, null, getUaaZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", Integer.class, new Object[]{getUaaZoneId()})).isEqualTo(count);
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

        assertThat(createdIdp.getName()).isEqualTo(idp.getName());
        assertThat(createdIdp.getOriginKey()).isEqualTo(idp.getOriginKey());
        assertThat(createdIdp.getType()).isEqualTo(idp.getType());
        assertThat(createdIdp.getConfig()).isEqualTo(idp.getConfig());
        assertThat(createdIdp.getConfig().getProviderDescription()).isEqualTo(providerDescription);

        assertThat(rawCreatedIdp)
                .containsEntry("name", idp.getName())
                .containsEntry("origin_key", idp.getOriginKey())
                .containsEntry("type", idp.getType());
        assertThat(JsonUtils.readValue((String) rawCreatedIdp.get("config"), UaaIdentityProviderDefinition.class)).isEqualTo(idp.getConfig());
        assertThat(rawCreatedIdp.get("identity_zone_id").toString().trim()).isEqualTo(uaaZoneId);

        idp.setId(createdIdp.getId());
        idp.setLastModified(new Timestamp(System.currentTimeMillis()));
        idp.setName("updated name");
        idp.setCreated(createdIdp.getCreated());
        idp.setConfig(new UaaIdentityProviderDefinition());
        idp.setOriginKey("new origin key");
        idp.setType(UAA);
        idp.setIdentityZoneId("somerandomID");
        createdIdp = jdbcIdentityProviderProvisioning.update(idp, uaaZoneId);

        assertThat(createdIdp.getName()).isEqualTo(idp.getName());
        assertThat(createdIdp.getOriginKey()).isEqualTo(rawCreatedIdp.get("origin_key"));
        assertThat(createdIdp.getType()).isEqualTo(UAA); //we don't allow other types anymore
        assertThat(createdIdp.getConfig()).isEqualTo(idp.getConfig());
        assertThat(Math.abs(idp.getLastModified().getTime() - createdIdp.getLastModified().getTime())).isLessThan(1001);
        assertThat(createdIdp.getVersion()).isEqualTo(Integer.parseInt(rawCreatedIdp.get("version").toString()) + 1);
        assertThat(createdIdp.getIdentityZoneId()).isEqualTo(uaaZoneId);
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
        assertThat(readAgain.getName()).isEqualTo(idp.getName());
        assertThat(readAgain.getOriginKey()).isEqualTo(idp.getOriginKey());
        assertThat(readAgain.getType()).isEqualTo(idp.getType());
        assertThat(readAgain.getConfig().getProviderDescription()).isEqualTo(providerDescription);
        OIDCIdentityProviderDefinition readAgainConfig = (OIDCIdentityProviderDefinition) readAgain.getConfig();
        assertThat(readAgainConfig.getIssuer()).isEqualTo(issuerURI);
        // update
        oidcIdentityProviderDefinition.setIssuer("https://new");
        idp.setId(readAgain.getId());
        idp.setLastModified(new Timestamp(System.currentTimeMillis()));
        idp.setConfig(oidcIdentityProviderDefinition);
        IdentityProvider updateIdp = jdbcIdentityProviderProvisioning.update(idp, uaaZoneId);
        readAgainConfig = (OIDCIdentityProviderDefinition) updateIdp.getConfig();
        assertThat(readAgainConfig.getIssuer()).isEqualTo("https://new");
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
        assertThat(readAgain.getName()).isEqualTo(idp.getName());
        assertThat(readAgain.getOriginKey()).isEqualTo(idp.getOriginKey());
        assertThat(readAgain.getType()).isEqualTo(idp.getType());
        assertThat(readAgain.getConfig().getProviderDescription()).isEqualTo(providerDescription);
        RawExternalOAuthIdentityProviderDefinition readAgainConfig = (RawExternalOAuthIdentityProviderDefinition) readAgain.getConfig();
        assertThat(readAgainConfig.getIssuer()).isEqualTo(issuerURI);
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
        assertThat(readAgainConfig.getIdpEntityId()).isEqualTo(entityId);
        // remove external_key to simulate existing IdP entry
        jdbcTemplate.update("update identity_provider set external_key='' where id = '" + createdIdp.getId() + "';");
        IdentityProvider readAgain = jdbcIdentityProviderProvisioning.retrieve(createdIdp.getId(), uaaZoneId);
        assertThat(readAgain.getName()).isEqualTo(idp.getName());
        assertThat(readAgain.getOriginKey()).isEqualTo(idp.getOriginKey());
        assertThat(readAgain.getType()).isEqualTo(idp.getType());
        assertThat(readAgain.getConfig().getProviderDescription()).isEqualTo(providerDescription);
        readAgainConfig = (SamlIdentityProviderDefinition) readAgain.getConfig();
        assertThat(readAgainConfig.getIdpEntityId()).isNull();
    }

    @Test
    void createIdentityProviderInOtherZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);

        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        Map<String, Object> rawCreatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", createdIdp.getId());

        assertThat(createdIdp.getName()).isEqualTo(idp.getName());
        assertThat(createdIdp.getOriginKey()).isEqualTo(idp.getOriginKey());
        assertThat(createdIdp.getType()).isEqualTo(idp.getType());
        assertThat(createdIdp.getConfig()).isEqualTo(idp.getConfig());

        assertThat(rawCreatedIdp)
                .containsEntry("name", idp.getName())
                .containsEntry("origin_key", idp.getOriginKey())
                .containsEntry("type", idp.getType());
        assertThat(JsonUtils.readValue((String) rawCreatedIdp.get("config"), AbstractIdentityProviderDefinition.class)).isEqualTo(idp.getConfig());
        assertThat(rawCreatedIdp).containsEntry("identity_zone_id", otherZoneId1);
    }

    @Test
    void createIdentityProviderWithNonUniqueOriginKeyInDefaultZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        assertThatExceptionOfType(IdpAlreadyExistsException.class).isThrownBy(() -> jdbcIdentityProviderProvisioning.create(idp, uaaZoneId));
    }

    @Test
    void createIdentityProviderWithNonUniqueOriginKeyInOtherZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        assertThatExceptionOfType(IdpAlreadyExistsException.class).isThrownBy(() -> jdbcIdentityProviderProvisioning.create(idp, otherZoneId1));
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

        assertThat(updatedIdp.getConfig()).isEqualTo(definition);
        assertThat(JsonUtils.readValue((String) rawUpdatedIdp.get("config"), LdapIdentityProviderDefinition.class)).isEqualTo(definition);
        assertThat(rawUpdatedIdp).containsEntry("identity_zone_id", getUaaZoneId());
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

        assertThat(updatedIdp.getConfig()).isEqualTo(definition);
        assertThat(JsonUtils.readValue((String) rawUpdatedIdp.get("config"), AbstractIdentityProviderDefinition.class)).isEqualTo(definition);
        assertThat(rawUpdatedIdp).containsEntry("identity_zone_id", otherZoneId1);
    }

    @Test
    void retrieveIdentityProviderById() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        IdentityProvider retrievedIdp = jdbcIdentityProviderProvisioning.retrieve(idp.getId(), otherZoneId1);
        assertThat(retrievedIdp.getId()).isEqualTo(idp.getId());
        assertThat(retrievedIdp.getConfig()).isEqualTo(idp.getConfig());
        assertThat(retrievedIdp.getName()).isEqualTo(idp.getName());
        assertThat(retrievedIdp.getOriginKey()).isEqualTo(idp.getOriginKey());
    }

    @Test
    void retrieveAll() {
        List<IdentityProvider> identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(uaaZoneId);
        int numberOfIdps = identityProviders.size();

        IdentityProvider defaultZoneIdp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(defaultZoneIdp, uaaZoneId);
        identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(uaaZoneId);
        assertThat(identityProviders).hasSize(numberOfIdps + 1);

        String otherOrigin = "otherOrigin-" + generator.generate();
        String otherZoneId = "otherZoneId-" + generator.generate();
        IdentityProvider otherZoneIdp = MultitenancyFixture.identityProvider(otherOrigin, otherZoneId);
        jdbcIdentityProviderProvisioning.create(otherZoneIdp, otherZoneId);

        identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(otherZoneId);
        assertThat(identityProviders).hasSize(1);
    }

    @Test
    void retrieveIdentityProviderByOriginInSameZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);

        IdentityProvider retrievedIdp = jdbcIdentityProviderProvisioning.retrieveByOrigin(idp.getOriginKey(), otherZoneId1);
        assertThat(retrievedIdp.getId()).isEqualTo(idp.getId());
        assertThat(retrievedIdp.getConfig()).isEqualTo(idp.getConfig());
        assertThat(retrievedIdp.getName()).isEqualTo(idp.getName());
        assertThat(retrievedIdp.getOriginKey()).isEqualTo(idp.getOriginKey());
    }

    @Test
    void retrieveIdentityProviderByOriginInDifferentZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        IdentityProvider idp1 = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcIdentityProviderProvisioning.retrieveByOrigin(idp1.getOriginKey(), otherZoneId2));
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
        assertThat(idsInResult).hasSize(expectedIdpIds.size());
        for (final String id : expectedIdpIds) {
            assertThat(idsInResult).contains(id);
        }
    }

    private static Stream<Arguments> retrieveActiveByTypes() {
        return Stream.of(
                new String[]{},
                new String[]{OAUTH20, OIDC10},
                new String[]{OAUTH20, OIDC10, SAML},
                new String[]{SAML},
                new String[]{OIDC10},
                new String[]{LDAP, UAA, OAUTH20, OIDC10},
                new String[]{LDAP, UAA, OAUTH20, LDAP, LDAP, OIDC10}, // contains duplicates
                (Object) new String[]{LDAP, UAA, OAUTH20, OIDC10, OIDC10, UAA} // contains duplicates
        ).map(Arguments::of);
    }

    private String createIdp(final String type, final String originKey, final String zoneId) {
        final String idpId = "idpId-" + generator.generate();
        final IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, idpId);
        idp.setId(idpId);
        idp.setType(type);
        final IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, zoneId);
        final String idpIdCreated = createdIdp.getId();
        assertThat(StringUtils.hasText(idpIdCreated)).isTrue();
        return idpIdCreated;
    }

    @Test
    void idpWithAliasExistsInZoneTrueCase() {
        final IdentityProvider<AbstractIdentityProviderDefinition> idpWithAlias = MultitenancyFixture.identityProvider(
                generator.generate(),
                otherZoneId1
        );
        idpWithAlias.setAliasZid(IdentityZone.getUaaZoneId());
        idpWithAlias.setAliasId(UUID.randomUUID().toString());
        jdbcIdentityProviderProvisioning.create(idpWithAlias, otherZoneId1);
        assertThat(jdbcIdentityProviderProvisioning.idpWithAliasExistsInZone(otherZoneId1)).isTrue();
    }

    @Test
    void idpWithAliasExistsInZoneFalseCase() {
        final IdentityProvider<AbstractIdentityProviderDefinition> idp = MultitenancyFixture.identityProvider(
                generator.generate(),
                otherZoneId2
        );
        jdbcIdentityProviderProvisioning.create(idp, otherZoneId2);
        assertThat(jdbcIdentityProviderProvisioning.idpWithAliasExistsInZone(otherZoneId2)).isFalse();
    }
}
