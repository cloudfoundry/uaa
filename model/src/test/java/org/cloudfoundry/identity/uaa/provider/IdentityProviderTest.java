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

}