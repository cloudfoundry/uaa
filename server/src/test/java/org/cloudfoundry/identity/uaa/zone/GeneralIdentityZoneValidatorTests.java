package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.CREATE;
import static org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter.DEFAULT_ZONE_SUBDOMAIN_PATH;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.DELETE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.MODIFY;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class GeneralIdentityZoneValidatorTests {

    @Mock
    GeneralIdentityZoneConfigurationValidator zoneConfigurationValidator;

    @InjectMocks
    GeneralIdentityZoneValidator validator;

    @Test
    void validateRightMode() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        checkValidationForModes(zone, config);
    }

    @Test
    void uaaZoneInactiveFails() {
        IdentityZone uaaZone = IdentityZoneHolder.getUaaZone();
        uaaZone.setActive(false);
        for (IdentityZoneValidator.Mode mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            try {
                validator.validate(uaaZone, mode);
                fail("");
            } catch (InvalidIdentityZoneDetailsException e) {
                assertThat(e.getMessage()).isEqualTo("The default zone cannot be set inactive.");
            }
        }
    }

    /**
     * On case-insensitive databases (default MySQL collations), a WHERE id = 'UAA' lookup
     * resolves to the system-zone row stored as 'uaa'. The validator must also treat all
     * case variants of "uaa" as the system zone and refuse to deactivate them.
     */
    @ParameterizedTest(name = "uaaZoneInactive blocked for id=''{0}''")
    @ValueSource(strings = {"UAA", "Uaa", "uAA", "uAa", "UaA", "UAa"})
    void uaaZoneInactive_withCasedId_fails(String caseVariant) {
        IdentityZone zone = new IdentityZone();
        zone.setId(caseVariant);
        zone.setSubdomain("");
        zone.setName(caseVariant);
        zone.setActive(false);
        for (IdentityZoneValidator.Mode mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            try {
                validator.validate(zone, mode);
                fail("Expected InvalidIdentityZoneDetailsException for id='" + caseVariant + "' mode=" + mode);
            } catch (InvalidIdentityZoneDetailsException e) {
                assertThat(e.getMessage()).isEqualTo("The default zone cannot be set inactive.");
            }
        }
    }

    @Test
    void reservedSubdomainDefault_rejectsForAllModes() {
        for (String subdomain : List.of(DEFAULT_ZONE_SUBDOMAIN_PATH,
                DEFAULT_ZONE_SUBDOMAIN_PATH.substring(0, 1).toUpperCase() + DEFAULT_ZONE_SUBDOMAIN_PATH.substring(1),
                DEFAULT_ZONE_SUBDOMAIN_PATH.toUpperCase())) {
            IdentityZone zone = MultitenancyFixture.identityZone("id", subdomain);
            for (IdentityZoneValidator.Mode mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
                try {
                    validator.validate(zone, mode);
                    fail("Expected InvalidIdentityZoneDetailsException for subdomain: " + subdomain + " mode: " + mode);
                } catch (InvalidIdentityZoneDetailsException e) {
                    assertThat(e.getMessage()).contains("reserved");
                }
            }
        }
    }

    @Test
    void otherZoneInactiveSucceeds() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        zone.setActive(false);
        checkValidationForModes(zone, config);
    }

    @ParameterizedTest
    @MethodSource("invalidSubdomains")
    void createOrUpdate_invalidSubdomain_fails(String subdomain, IdentityZoneValidator.Mode mode) {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        zone.setSubdomain(subdomain);

        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneDetailsException.class)
                .hasMessage("The subdomain must contain only ASCII letters, digits, or hyphens, " +
                        "and must start and end with a letter or digit.");
        verifyNoInteractions(zoneConfigurationValidator);
    }

    private static Stream<Arguments> invalidSubdomains() {
        return Stream.of(null, "", " ", "my zone", "my.zone", "my_zone", "-zone", "zone-",
                        "zone/path", "zone\\path", "zone?query", "zone#fragment", "zone%2fpath",
                        "zone%252fpath", ".", "..", "zone;param", "zone@host", "zone:8080",
                        "zöne", "zone\r\n")
                .flatMap(subdomain -> Stream.of(CREATE, MODIFY).map(mode -> Arguments.of(subdomain, mode)));
    }

    @ParameterizedTest
    @MethodSource("validSubdomains")
    void createOrUpdate_validSubdomain_succeeds(String subdomain, IdentityZoneValidator.Mode mode) throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("id", subdomain);
        zone.setSubdomain(subdomain);
        when(zoneConfigurationValidator.validate(zone, mode)).thenReturn(zone.getConfig());

        assertThat(validator.validate(zone, mode)).isSameAs(zone);
        verify(zoneConfigurationValidator).validate(zone, mode);
    }

    private static Stream<Arguments> validSubdomains() {
        return Stream.of("a", "0", "Zone123", "my-zone", "my--zone",
                        "550e8400-e29b-41d4-a716-446655440000", "a".repeat(255))
                .flatMap(subdomain -> Stream.of(CREATE, MODIFY).map(mode -> Arguments.of(subdomain, mode)));
    }

    @ParameterizedTest
    @MethodSource("overlongSubdomains")
    void createOrUpdate_overlongSubdomain_fails(int length, IdentityZoneValidator.Mode mode) {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "a".repeat(length));

        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneDetailsException.class)
                .hasMessage("The subdomain must not exceed 255 characters.");
        verifyNoInteractions(zoneConfigurationValidator);
    }

    private static Stream<Arguments> overlongSubdomains() {
        return Stream.of(256, 1024)
                .flatMap(length -> Stream.of(CREATE, MODIFY).map(mode -> Arguments.of(length, mode)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"uaa", "UAA", "Uaa"})
    void update_defaultZoneWithEmptySubdomain_succeeds(String id) throws Exception {
        IdentityZone zone = IdentityZone.getUaa();
        zone.setId(id);
        when(zoneConfigurationValidator.validate(zone, MODIFY)).thenReturn(zone.getConfig());

        assertThat(validator.validate(zone, MODIFY)).isSameAs(zone);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"zone/path", "zone?query", "zone#fragment", " "})
    void update_defaultZoneWithInvalidSubdomain_fails(String subdomain) {
        IdentityZone zone = IdentityZone.getUaa();
        zone.setSubdomain(subdomain);

        assertThatThrownBy(() -> validator.validate(zone, MODIFY))
                .isInstanceOf(InvalidIdentityZoneDetailsException.class);
        verifyNoInteractions(zoneConfigurationValidator);
    }

    @ParameterizedTest
    @EnumSource(value = IdentityZoneValidator.Mode.class, names = {"CREATE", "MODIFY"})
    void createOrUpdate_withoutZoneId_invalidSubdomain_fails(IdentityZoneValidator.Mode mode) {
        IdentityZone zone = MultitenancyFixture.identityZone(null, "zone/path");

        assertThatThrownBy(() -> validator.validate(zone, mode))
                .isInstanceOf(InvalidIdentityZoneDetailsException.class);
    }

    @Test
    void delete_legacyInvalidSubdomain_succeeds() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "zone/path");
        when(zoneConfigurationValidator.validate(zone, DELETE)).thenReturn(zone.getConfig());

        assertThat(validator.validate(zone, DELETE)).isSameAs(zone);
    }

    private void checkValidationForModes(IdentityZone zone, IdentityZoneConfiguration config) throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        for (IdentityZoneValidator.Mode mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            reset(zoneConfigurationValidator);
            when(zoneConfigurationValidator.validate(any(), any())).thenReturn(config);
            validator.validate(zone, mode);
            verify(zoneConfigurationValidator, times(1)).validate(same(zone), same(mode));
        }
    }
}
