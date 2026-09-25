package org.cloudfoundry.identity.uaa.spiffe;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SpiffePropertiesTests {

    @Test
    void appliesDefaultsWhenOptionalValuesAreNull() {
        SpiffeProperties props = new SpiffeProperties("example.org", "PEM", null, null, null);

        assertThat(props.trustDomain()).isEqualTo("example.org");
        assertThat(props.instanceIdentityCa()).isEqualTo("PEM");
        assertThat(props.jwtSvidTtlSeconds()).isEqualTo(3600L);
        assertThat(props.popFreshnessSeconds()).isEqualTo(60);
        assertThat(props.popEnabled()).isTrue();
    }

    @Test
    void retainsExplicitValues() {
        SpiffeProperties props = new SpiffeProperties("td", "ca", 120L, 5, false);

        assertThat(props.jwtSvidTtlSeconds()).isEqualTo(120L);
        assertThat(props.popFreshnessSeconds()).isEqualTo(5);
        assertThat(props.popEnabled()).isFalse();
    }
}
