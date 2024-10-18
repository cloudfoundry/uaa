package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

class IdentityZoneTest {

    @Test
    void getUaa() {
        Calendar calendar = Calendar.getInstance();
        calendar.set(2000, Calendar.JANUARY, 1, 0, 0, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        Date expectedDate = calendar.getTime();

        IdentityZone actual = IdentityZone.getUaa();
        assertThat(actual.getId()).isEqualTo("uaa");
        assertThat(actual.getSubdomain()).isEmpty();
        assertThat(actual.getName()).isEqualTo("uaa");
        assertThat(actual.getVersion()).isZero();
        assertThat(actual.getDescription()).isEqualTo("The system zone for backwards compatibility");
        assertThat(actual.isActive()).isTrue();
        assertThat(actual.getCreated()).isEqualTo(expectedDate);
        assertThat(actual.getLastModified()).isEqualTo(expectedDate);

        // Validate that the config is the result of `new IdentityZoneConfiguration()`
        assertThat(actual.getConfig()).usingRecursiveComparison().isEqualTo(new IdentityZoneConfiguration());
    }

    private static class IsUaaArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            IdentityZone notUaa = new IdentityZone();
            notUaa.setId("something");

            IdentityZone uaa = new IdentityZone();
            uaa.setId("uaa");

            return Stream.of(
                    Arguments.of(IdentityZone.getUaa(), true, "true:getUaa"),
                    Arguments.of(uaa, true, "true:id=uaa"),
                    Arguments.of(new IdentityZone(), false, "false:new"),
                    Arguments.of(notUaa, false, "false:id=something")
            );
        }
    }

    @ParameterizedTest(name = "[{index}] {2}")
    @ArgumentsSource(IsUaaArgumentsSource.class)
    void isUaa_usesOnlyId(IdentityZone identityZone, boolean isUaa, String ignoredMessage) {
        assertThat(identityZone.isUaa()).isEqualTo(isUaa);
    }

    @Test
    void getUaaZoneId() {
        assertThat(IdentityZone.getUaaZoneId()).isEqualTo("uaa");
    }

    private static class EqualsArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            IdentityZone zoneWithIdUaa = new IdentityZone();
            zoneWithIdUaa.setId("uaa");

            IdentityZone zone1 = new IdentityZone();
            zone1.setId("id1");
            zone1.setSubdomain("subdomain");
            IdentityZone zone2 = new IdentityZone();
            zone2.setId("id2");
            zone2.setSubdomain("subdomain");

            return Stream.of(
                    Arguments.of(new IdentityZone(), new IdentityZone(), true, "new=new"),
                    Arguments.of(IdentityZone.getUaa(), zoneWithIdUaa, true, "uaa=uaa"),
                    Arguments.of(zone1, zone1, true, "zone1=zone1"),
                    Arguments.of(zone1, zone2, false, "zone1!=zone2"),
                    Arguments.of(zone2, zone1, false, "zone2!=zone1"),
                    Arguments.of(zone1, null, false, "zone1=null"),
                    Arguments.of(zone1, "blah", false, "zone1=string")
            );
        }
    }

    @ParameterizedTest(name = "[{index}] {3}")
    @ArgumentsSource(EqualsArgumentsSource.class)
    void equals_usesOnlyId(IdentityZone zone1, Object zone2, boolean areEqual, String ignoredMessage) {
        assertThat(zone1.equals(zone2)).isEqualTo(areEqual);
    }

    private static class HashCodeArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            IdentityZone zone1 = new IdentityZone();
            zone1.setSubdomain("subdomain");
            zone1.setId("asdf");
            IdentityZone nullIdZone = new IdentityZone();

            final int prime = 59;
            final int nullVal = prime + 43;
            return Stream.of(
                    Arguments.of(zone1, prime + "asdf".hashCode(), "asdf"),
                    Arguments.of(zone1, prime + "asdf".hashCode(), "asdf"),
                    Arguments.of(IdentityZone.getUaa(), prime + "uaa".hashCode(), "uaa"),
                    Arguments.of(IdentityZone.getUaa(), prime + "uaa".hashCode(), "uaa"),
                    Arguments.of(nullIdZone, nullVal, "null id"),
                    Arguments.of(nullIdZone, nullVal, "null id")
            );
        }
    }

    @ParameterizedTest(name = "[{index}] {2}")
    @ArgumentsSource(HashCodeArgumentsSource.class)
    void hashCode_usesOnlyId(IdentityZone zone, int expectedHashCode, String ignoredMessage) {
        assertThat(zone.hashCode()).isEqualTo(expectedHashCode);
    }

    @Test
    void deserialize() {
        final String sampleIdentityZoneJson = getResourceAsString(getClass(), "SampleIdentityZone.json");
        IdentityZone sampleIdentityZone = JsonUtils.readValue(sampleIdentityZoneJson, IdentityZone.class);
        assertThat(sampleIdentityZone).isNotNull()
                .returns("f7758816-ab47-48d9-9d24-25b10b92d4cc", IdentityZone::getId)
                .returns("demo", IdentityZone::getSubdomain);
        assertThat(sampleIdentityZone.getConfig().getUserConfig().getDefaultGroups()).isEqualTo(List.of("openid", "password.write", "uaa.user", "approvals.me",
                "profile", "roles", "user_attributes", "uaa.offline_token"));
        assertThat(sampleIdentityZone.getConfig().getUserConfig().resultingAllowedGroups()).isEqualTo(Set.of("openid", "password.write", "uaa.user", "approvals.me",
                "profile", "roles", "user_attributes", "uaa.offline_token",
                "scim.me", "cloud_controller.user"));
        assertThat(sampleIdentityZone.getConfig().getUserConfig().getMaxUsers()).isEqualTo(1000);
        assertThat(sampleIdentityZone.getConfig().getUserConfig().isCheckOriginEnabled()).isTrue();
    }
}