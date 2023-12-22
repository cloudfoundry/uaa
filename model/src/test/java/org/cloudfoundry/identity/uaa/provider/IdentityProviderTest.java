package org.cloudfoundry.identity.uaa.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class IdentityProviderTest {

    private static IdentityProvider<OIDCIdentityProviderDefinition> idp;

    @BeforeAll
    static void beforeAll() {
        idp = new IdentityProvider<>();
        idp.setId("12345");
        idp.setName("some-name");
        idp.setOriginKey("some-origin");
        idp.setAliasZid("custom-zone");
        idp.setAliasId("id-of-mirrored-idp");
        idp.setActive(true);
        idp.setIdentityZoneId(UAA);
        final OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setIssuer("issuer");
        idp.setConfig(config);
    }

    @Test
    void testToString_ShouldContainAliasProperties() {
        assertThat(idp).hasToString("IdentityProvider{id='12345', originKey='some-origin', name='some-name', type='oidc1.0', active=true, aliasId='id-of-mirrored-idp', aliasZid='custom-zone'}");
    }

    @Test
    void testEqualsAndHashCode() {
        final IdentityProvider<OIDCIdentityProviderDefinition> idp2 = new IdentityProvider<>();
        idp2.setId("12345");
        idp2.setName("some-name");
        idp2.setOriginKey("some-origin");
        idp2.setAliasZid("custom-zone");
        idp2.setAliasId("id-of-mirrored-idp");
        idp2.setActive(true);
        idp2.setIdentityZoneId(UAA);
        final OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setIssuer("issuer");
        idp2.setConfig(config);

        idp2.setCreated(idp.getCreated());
        idp2.setLastModified(idp.getLastModified());

        assertThat(idp.equals(idp2)).isTrue();
        assertThat(idp).hasSameHashCodeAs(idp2);

        idp2.setAliasZid(null);
        assertThat(idp.equals(idp2)).isFalse();

        idp2.setAliasZid("custom-zone");
        idp2.setAliasId(null);
        assertThat(idp.equals(idp2)).isFalse();
    }

}