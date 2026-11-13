package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedConstruction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class V2_7_3__StoreSubDomainAsLowerCase_Tests {

    private IdentityZoneProvisioning provisioning;
    private V2_7_3__StoreSubDomainAsLowerCase migration;
    private RandomValueStringGenerator generator;
    private Context context;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private Connection connection;

    @AfterEach
    void closeConnection() throws SQLException {
        try {
            jdbcTemplate.execute("delete from identity_zone where id != 'uaa'");
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

    @BeforeEach
    void setUpDuplicateZones() throws SQLException {
        jdbcTemplate.execute("delete from identity_zone where id != 'uaa'");
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        migration = new V2_7_3__StoreSubDomainAsLowerCase();
        generator = new RandomValueStringGenerator(6);
        connection = jdbcTemplate.getDataSource().getConnection();
        context = mock(Context.class);
        when(context.getConnection()).thenReturn(connection);
    }

    @Test
    void ensureThatSubdomainsGetLowerCased() {
        List<String> subdomains = Arrays.asList(
                "Zone1" + generator.generate(),
                "Zone2" + generator.generate(),
                "Zone3" + generator.generate(),
                "Zone4+generator.generate()"
        );

        for (String subdomain : subdomains) {
            IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
            IdentityZone created = provisioning.create(zone);
            assertThat(created.getSubdomain()).isEqualTo(subdomain.toLowerCase());
            jdbcTemplate.update("UPDATE identity_zone SET subdomain = ? WHERE id = ?", subdomain, subdomain);
            assertThat(jdbcTemplate.queryForObject("SELECT subdomain FROM identity_zone where id = ?", String.class, subdomain)).isEqualTo(subdomain);
        }

        migration.migrate(context);
        for (String subdomain : subdomains) {
            for (IdentityZone zone :
                    Arrays.asList(
                            provisioning.retrieve(subdomain),
                            provisioning.retrieveBySubdomain(subdomain.toLowerCase()),
                            provisioning.retrieveBySubdomain(subdomain)
                    )
            ) {
                assertThat(zone).isNotNull();
                assertThat(zone.getId()).isEqualTo(subdomain);
                assertThat(zone.getSubdomain()).isEqualTo(subdomain.toLowerCase());
            }
        }
    }

    @Test
    void duplicateSubdomains() {
        checkDbIsCaseSensitive();
        List<String> ids = Arrays.asList(
                "id1" + generator.generate().toLowerCase(),
                "id2" + generator.generate().toLowerCase(),
                "id3" + generator.generate().toLowerCase(),
                "id4" + generator.generate().toLowerCase(),
                "id5" + generator.generate().toLowerCase()
        );
        List<String> subdomains = Arrays.asList(
                "domain1",
                "Domain1",
                "doMain1",
                "domain4" + generator.generate().toLowerCase(),
                "domain5" + generator.generate().toLowerCase()
        );
        for (int i = 0; i < ids.size(); i++) {
            IdentityZone zone = MultitenancyFixture.identityZone(ids.get(i), subdomains.get(i));
            zone.setSubdomain(subdomains.get(i)); //mixed case
            createIdentityZoneThroughSQL(zone);
        }
        IdentityZone lowercase = provisioning.retrieveBySubdomain("domain1");
        IdentityZone mixedcase = provisioning.retrieveBySubdomain("Domain1");
        assertThat(mixedcase.getId()).isEqualTo(lowercase.getId());

        migration.migrate(context);

        for (IdentityZone zone : provisioning.retrieveAll()) {
            //ensure we converted to lower case
            assertThat(zone.getSubdomain()).isEqualTo(zone.getSubdomain().toLowerCase());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"tr-TR", "az-AZ"})
    @ResourceLock(Resources.LOCALE)
    void migratesSubdomain_withNonEnglishLocale_usesAsciiLowercase(String languageTag) {
        String id = "locale-zone-" + generator.generate();
        String subdomain = "I-ZONE-" + languageTag;
        String lowercaseSubdomain = subdomain.toLowerCase(Locale.ROOT);
        IdentityZone zone = MultitenancyFixture.identityZone(id, lowercaseSubdomain);
        zone.setSubdomain(subdomain);
        createIdentityZoneThroughSQL(zone);

        Locale originalLocale = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag(languageTag));
            migration.migrate(context);

            assertThat(provisioning.retrieve(id).getSubdomain()).isEqualTo(lowercaseSubdomain);
            assertThat(provisioning.retrieveBySubdomain(subdomain).getId()).isEqualTo(id);
        } finally {
            Locale.setDefault(originalLocale);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"tr-TR", "az-AZ"})
    @ResourceLock(Resources.LOCALE)
    void migratesDuplicateSubdomains_withNonEnglishLocale_usesAsciiLowercase(String languageTag) {
        checkDbIsCaseSensitive();
        String uppercaseId = "uppercase-zone-" + generator.generate();
        String lowercaseId = "lowercase-zone-" + generator.generate();
        String subdomain = "I-DUPLICATE-" + languageTag;
        String lowercaseSubdomain = subdomain.toLowerCase(Locale.ROOT);
        IdentityZone uppercaseZone = MultitenancyFixture.identityZone(uppercaseId, lowercaseSubdomain);
        uppercaseZone.setSubdomain(subdomain);
        createIdentityZoneThroughSQL(uppercaseZone);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone(lowercaseId, lowercaseSubdomain));

        Locale originalLocale = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag(languageTag));
            migration.migrate(context);

            assertThat(List.of(provisioning.retrieve(uppercaseId).getSubdomain(),
                    provisioning.retrieve(lowercaseId).getSubdomain()))
                    .contains(lowercaseSubdomain)
                    .doesNotHaveDuplicates()
                    .allSatisfy(value -> assertThat(value).matches(lowercaseSubdomain + "(?:-[a-z0-9]{3})?"));
        } finally {
            Locale.setDefault(originalLocale);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {62, 63})
    void migratesDuplicateSubdomains_withUnsafeRandomBytes_usesAlphanumericSuffix(int randomByte) {
        checkDbIsCaseSensitive();
        migration.migrate(context);
        String subdomain = "suffix-zone-" + randomByte;
        String uppercaseId = "suffix-uppercase-" + generator.generate();
        String lowercaseId = "suffix-lowercase-" + generator.generate();
        IdentityZone uppercaseZone = MultitenancyFixture.identityZone(uppercaseId, subdomain);
        uppercaseZone.setSubdomain(subdomain.toUpperCase(Locale.ROOT));
        createIdentityZoneThroughSQL(uppercaseZone);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone(lowercaseId, subdomain));

        // These bytes produce '-' or '_' with the unrestricted generator's alphabet.
        try (MockedConstruction<SecureRandom> ignored = mockConstruction(SecureRandom.class,
                (random, constructionContext) -> doAnswer(invocation -> {
                    Arrays.fill(invocation.getArgument(0, byte[].class), (byte) randomByte);
                    return null;
                }).when(random).nextBytes(any(byte[].class)))) {
            migration.migrate(context);
        }

        assertThat(List.of(provisioning.retrieve(uppercaseId).getSubdomain(),
                provisioning.retrieve(lowercaseId).getSubdomain()))
                .contains(subdomain)
                .doesNotHaveDuplicates()
                .allSatisfy(value -> assertThat(value).matches(subdomain + "(?:-[a-z0-9]{3})?"));
    }

    @ParameterizedTest
    @ValueSource(ints = {251, 252, 255})
    void migratesDuplicateSubdomains_nearMaximumLength_boundsRenamedSubdomain(int length) {
        checkDbIsCaseSensitive();
        String prefix = "length-" + length + "-";
        String subdomain = prefix + "a".repeat(length - prefix.length());
        String uppercaseId = "length-uppercase-" + generator.generate();
        String lowercaseId = "length-lowercase-" + generator.generate();
        IdentityZone uppercaseZone = MultitenancyFixture.identityZone(uppercaseId, subdomain);
        uppercaseZone.setSubdomain(subdomain.toUpperCase(Locale.ROOT));
        createIdentityZoneThroughSQL(uppercaseZone);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone(lowercaseId, subdomain));

        migration.migrate(context);

        List<String> migratedSubdomains = List.of(provisioning.retrieve(uppercaseId).getSubdomain(),
                provisioning.retrieve(lowercaseId).getSubdomain());
        assertThat(migratedSubdomains).contains(subdomain).doesNotHaveDuplicates();
        assertThat(migratedSubdomains).filteredOn(value -> !value.equals(subdomain))
                .singleElement(STRING)
                .hasSize(Math.min(length + 4, 255))
                .matches(subdomain.substring(0, Math.min(length, 251)) + "-[a-z0-9]{3}");
    }

    @Test
    void migratesDuplicateSubdomains_truncatedCandidateAlreadyExists_retriesSuffix() {
        checkDbIsCaseSensitive();
        // Normalize probe rows before controlling suffix generation for the target collision.
        migration.migrate(context);
        String subdomain = "collision" + "a".repeat(246);
        String truncatedSubdomain = subdomain.substring(0, 251);
        String uppercaseId = "collision-uppercase-" + generator.generate();
        String lowercaseId = "collision-lowercase-" + generator.generate();
        String existingId = "collision-existing-" + generator.generate();
        IdentityZone uppercaseZone = MultitenancyFixture.identityZone(uppercaseId, subdomain);
        uppercaseZone.setSubdomain(subdomain.toUpperCase(Locale.ROOT));
        createIdentityZoneThroughSQL(uppercaseZone);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone(lowercaseId, subdomain));
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone(existingId, truncatedSubdomain + "-111"));

        try (MockedConstruction<SecureRandom> ignored = mockConstruction(SecureRandom.class,
                (random, constructionContext) -> doAnswer(invocation -> {
                    Arrays.fill(invocation.getArgument(0, byte[].class), (byte) 0);
                    return null;
                }).doAnswer(invocation -> {
                    Arrays.fill(invocation.getArgument(0, byte[].class), (byte) 1);
                    return null;
                }).when(random).nextBytes(any(byte[].class)))) {
            migration.migrate(context);
        }

        assertThat(List.of(provisioning.retrieve(uppercaseId).getSubdomain(),
                provisioning.retrieve(lowercaseId).getSubdomain()))
                .containsExactlyInAnyOrder(subdomain, truncatedSubdomain + "-222");
        assertThat(provisioning.retrieve(existingId).getSubdomain()).isEqualTo(truncatedSubdomain + "-111");
    }

    @ParameterizedTest
    @ValueSource(strings = {"-legacy", "legacy-", "zone/path", "zone_legacy", "zone.legacy",
            "zone?query", " legacy", "zöne", "-ö-"})
    void migratesDuplicateSubdomains_invalidLegacyBase_usesValidFallback(String subdomain) {
        checkDbIsCaseSensitive();
        String uppercaseId = "unsafe-uppercase-" + generator.generate();
        String lowercaseId = "unsafe-lowercase-" + generator.generate();
        IdentityZone uppercaseZone = MultitenancyFixture.identityZone(uppercaseId, subdomain);
        uppercaseZone.setSubdomain(subdomain.toUpperCase(Locale.ROOT));
        createIdentityZoneThroughSQL(uppercaseZone);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone(lowercaseId, subdomain));

        migration.migrate(context);

        List<String> migratedSubdomains = List.of(provisioning.retrieve(uppercaseId).getSubdomain(),
                provisioning.retrieve(lowercaseId).getSubdomain());
        assertThat(migratedSubdomains).contains(subdomain).doesNotHaveDuplicates();
        assertThat(migratedSubdomains).filteredOn(value -> !value.equals(subdomain))
                .singleElement(STRING)
                .matches("zone-[a-z0-9]{3}")
                .satisfies(value -> assertThat(UaaUrlUtils.isValidSubdomain(value)).isTrue());
    }

    @ParameterizedTest
    @ValueSource(ints = {64, 128, 255})
    void migratesLegacySubdomain_unicodeLowercaseExpansion_doesNotExceedColumnLimit(int length) {
        String subdomain = "İ".repeat(length);
        IdentityZone zone = MultitenancyFixture.identityZone("unicode-zone-" + length, "legacy");
        zone.setSubdomain(subdomain);
        createIdentityZoneThroughSQL(zone);

        assertThatCode(() -> migration.migrate(context)).doesNotThrowAnyException();

        String normalized = subdomain.toLowerCase(Locale.ROOT);
        assertThat(provisioning.retrieve(zone.getId()).getSubdomain())
                .isEqualTo(normalized.length() > 255 ? subdomain : normalized)
                .hasSizeLessThanOrEqualTo(255);
    }

    @ParameterizedTest
    @ValueSource(ints = {18, 255})
    void migratesDuplicateSubdomains_randomSuffixRepeatedlyCollides_usesDeterministicFallback(int length) {
        checkDbIsCaseSensitive();
        migration.migrate(context);
        String subdomain = "r".repeat(length);
        String randomCandidate = subdomain.substring(0, Math.min(length, 251)) + "-111";
        String fallbackBase = subdomain.substring(0, Math.min(length, 253));
        IdentityZone uppercaseZone = MultitenancyFixture.identityZone("repeated-uppercase", subdomain);
        uppercaseZone.setSubdomain(subdomain.toUpperCase(Locale.ROOT));
        createIdentityZoneThroughSQL(uppercaseZone);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone("repeated-lowercase", subdomain));
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone("repeated-existing", randomCandidate));
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone("fallback-existing", fallbackBase + "-0"));

        AtomicInteger attempts = new AtomicInteger();
        try (MockedConstruction<SecureRandom> ignored = mockConstruction(SecureRandom.class,
                (random, constructionContext) -> doAnswer(invocation -> {
                    if (attempts.incrementAndGet() > 20) {
                        throw new IllegalStateException("Random suffix generation did not make progress.");
                    }
                    Arrays.fill(invocation.getArgument(0, byte[].class), (byte) 0);
                    return null;
                }).when(random).nextBytes(any(byte[].class)))) {
            assertThatCode(() -> migration.migrate(context)).doesNotThrowAnyException();
        }

        assertThat(List.of(provisioning.retrieve("repeated-uppercase").getSubdomain(),
                provisioning.retrieve("repeated-lowercase").getSubdomain()))
                .containsExactlyInAnyOrder(subdomain, fallbackBase + "-1");
        assertThat(provisioning.retrieve("repeated-existing").getSubdomain()).isEqualTo(randomCandidate);
        assertThat(provisioning.retrieve("fallback-existing").getSubdomain()).isEqualTo(fallbackBase + "-0");
    }

    @Test
    void migratesInvalidDuplicateGroups_sharedFallbackBase_reservesNewNames() {
        checkDbIsCaseSensitive();
        IdentityZone firstUppercase = MultitenancyFixture.identityZone("first-uppercase", "-first");
        firstUppercase.setSubdomain("-FIRST");
        IdentityZone secondUppercase = MultitenancyFixture.identityZone("second-uppercase", "second/path");
        secondUppercase.setSubdomain("SECOND/PATH");
        createIdentityZoneThroughSQL(firstUppercase);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone("first-lowercase", "-first"));
        createIdentityZoneThroughSQL(secondUppercase);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone("second-lowercase", "second/path"));

        AtomicInteger attempts = new AtomicInteger();
        try (MockedConstruction<SecureRandom> ignored = mockConstruction(SecureRandom.class,
                (random, constructionContext) -> doAnswer(invocation -> {
                    if (attempts.incrementAndGet() > 20) {
                        throw new IllegalStateException("Random suffix generation did not make progress.");
                    }
                    Arrays.fill(invocation.getArgument(0, byte[].class), (byte) 0);
                    return null;
                }).when(random).nextBytes(any(byte[].class)))) {
            migration.migrate(context);
        }

        assertThat(List.of(provisioning.retrieve("first-uppercase").getSubdomain(),
                provisioning.retrieve("first-lowercase").getSubdomain(),
                provisioning.retrieve("second-uppercase").getSubdomain(),
                provisioning.retrieve("second-lowercase").getSubdomain()))
                .containsExactlyInAnyOrder("-first", "second/path", "zone-111", "zone-0");
    }

    @ParameterizedTest
    @ValueSource(strings = {"idempotent-zone", "-idempotent"})
    void migratesDuplicateSubdomains_runTwice_leavesZonesAndDefaultZoneUnchanged(String subdomain) {
        checkDbIsCaseSensitive();
        IdentityZone uppercaseZone = MultitenancyFixture.identityZone("idempotent-uppercase", subdomain);
        uppercaseZone.setSubdomain(subdomain.toUpperCase(Locale.ROOT));
        createIdentityZoneThroughSQL(uppercaseZone);
        createIdentityZoneThroughSQL(MultitenancyFixture.identityZone("idempotent-lowercase", subdomain));
        IdentityZone defaultZone = provisioning.retrieve("uaa");

        migration.migrate(context);
        IdentityZone firstUppercase = provisioning.retrieve("idempotent-uppercase");
        IdentityZone firstLowercase = provisioning.retrieve("idempotent-lowercase");
        migration.migrate(context);

        assertThat(provisioning.retrieve("idempotent-uppercase")).usingRecursiveComparison().isEqualTo(firstUppercase);
        assertThat(provisioning.retrieve("idempotent-lowercase")).usingRecursiveComparison().isEqualTo(firstLowercase);
        assertThat(provisioning.retrieve("uaa")).usingRecursiveComparison().isEqualTo(defaultZone);
    }

    public void checkDbIsCaseSensitive() {
        String usubdomain = "TEST_UPPER_" + generator.generate();
        String lsubdomain = usubdomain.toLowerCase();

        IdentityZone uppercaseZone = MultitenancyFixture.identityZone("case-probe-uppercase", lsubdomain);
        uppercaseZone.setSubdomain(usubdomain);
        IdentityZone lowercaseZone = MultitenancyFixture.identityZone("case-probe-lowercase", lsubdomain);
        try {
            createIdentityZoneThroughSQL(uppercaseZone);
            createIdentityZoneThroughSQL(lowercaseZone);
        } catch (DuplicateKeyException _) {
            assumeTrue(false, "DB is not case sensitive. No need for this test");
        } finally {
            jdbcTemplate.update("delete from identity_zone where id in (?, ?)",
                    uppercaseZone.getId(), lowercaseZone.getId());
        }
    }

    protected void createIdentityZoneThroughSQL(IdentityZone identityZone) {
        String idZoneFields = "id,version,created,lastmodified,name,subdomain,description";
        String createIdentityZoneSql = "insert into identity_zone(" + idZoneFields + ") values (?,?,?,?,?,?,?)";

        jdbcTemplate.update(createIdentityZoneSql, ps -> {
            ps.setString(1, identityZone.getId().trim());
            ps.setInt(2, identityZone.getVersion());
            ps.setTimestamp(3, new Timestamp(new Date().getTime()));
            ps.setTimestamp(4, new Timestamp(new Date().getTime()));
            ps.setString(5, identityZone.getName());
            ps.setString(6, identityZone.getSubdomain());
            ps.setString(7, identityZone.getDescription());
        });
    }
}
