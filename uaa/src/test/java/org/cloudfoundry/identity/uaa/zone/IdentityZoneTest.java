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
import java.util.stream.Stream;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

class IdentityZoneTest {

    @Test
    void getUaa() {

        Calendar calendar = Calendar.getInstance();
        calendar.set(2000, Calendar.JANUARY, 1, 0, 0, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        Date expectedDate = calendar.getTime();

        IdentityZone actual = IdentityZone.getUaa();

        assertThat(actual.getId(), is("uaa"));
        assertThat(actual.getSubdomain(), is(""));
        assertThat(actual.getName(), is("uaa"));
        assertThat(actual.getVersion(), is(0));
        assertThat(actual.getDescription(), is("The system zone for backwards compatibility"));
        assertThat(actual.isActive(), is(true));
        assertThat(actual.getCreated(), is(expectedDate));
        assertThat(actual.getLastModified(), is(expectedDate));

        // TODO: Validate that the config is the result of `new IdentityZoneConfiguration()`
        // Currently this is not possible because not all objects have a `.equals()` method
//        assertThat(actual.getConfig(), is(new IdentityZoneConfiguration()));
    }

    private static class IsUaaArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            IdentityZone notUaa = new IdentityZone();
            notUaa.setId("something");

            IdentityZone uaa = new IdentityZone();
            uaa.setId("uaa");

            return Stream.of(
                    Arguments.of(IdentityZone.getUaa(), true),
                    Arguments.of(uaa, true),
                    Arguments.of(new IdentityZone(), false),
                    Arguments.of(notUaa, false)
            );
        }
    }

    @ParameterizedTest
    @ArgumentsSource(IsUaaArgumentsSource.class)
    void isUaa_usesOnlyId(IdentityZone identityZone, boolean isUaa) {
        assertThat(identityZone.isUaa(), is(isUaa));
    }

    @Test
    void getUaaZoneId() {
        assertThat(IdentityZone.getUaaZoneId(), is("uaa"));
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
                    Arguments.of(new IdentityZone(), new IdentityZone(), true),
                    Arguments.of(IdentityZone.getUaa(), zoneWithIdUaa, true),
                    Arguments.of(zone1, zone2, false)
            );
        }
    }

    @ParameterizedTest
    @ArgumentsSource(EqualsArgumentsSource.class)
    void equals_usesOnlyId(IdentityZone zone1, IdentityZone zone2, boolean areEqual) {
        assertThat(zone1.equals(zone2), is(areEqual));
        assertThat(zone2.equals(zone1), is(areEqual));
    }

    private static class HashCodeArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            IdentityZone zone1 = new IdentityZone();
            zone1.setSubdomain("subdomain");
            zone1.setId("asdf");

            return Stream.of(
                    Arguments.of(zone1, 31 + "asdf".hashCode()),
                    Arguments.of(IdentityZone.getUaa(), 31 + "uaa".hashCode())
            );
        }
    }

    @ParameterizedTest
    @ArgumentsSource(HashCodeArgumentsSource.class)
    void hashCode_usesOnlyId(IdentityZone zone, int expectedHashCode) {
        assertThat(zone.hashCode(), is(expectedHashCode));
    }

    @Test
    void deserialize() {
        final String sampleIdentityZone = getResourceAsString(getClass(), "SampleIdentityZone.json");

        JsonUtils.readValue(sampleIdentityZone, IdentityZone.class);
    }
}