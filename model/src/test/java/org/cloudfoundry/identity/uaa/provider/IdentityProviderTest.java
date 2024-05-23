package org.cloudfoundry.identity.uaa.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

import org.junit.jupiter.api.Test;

class IdentityProviderTest {

    @Test
    void testToString_ShouldContainAliasProperties() {
        final IdentityProvider<OIDCIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setId("12345");
        idp.setName("some-name");
        idp.setOriginKey("some-origin");
        idp.setAliasZid("custom-zone");
        idp.setAliasId("id-of-alias-idp");
        idp.setActive(true);
        idp.setIdentityZoneId(UAA);
        final OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setIssuer("issuer");
        idp.setConfig(config);

        assertThat(idp.getAliasId()).isEqualTo("id-of-alias-idp");
        assertThat(idp.getAliasZid()).isEqualTo("custom-zone");
        assertThat(idp).hasToString("IdentityProvider{id='12345', identityZoneId='uaa', originKey='some-origin', name='some-name', type='oidc1.0', active=true, aliasId='id-of-alias-idp', aliasZid='custom-zone'}");
    }

    @Test
    void testToString_AliasPropertiesAndIdzIdNull() {
        final IdentityProvider<OIDCIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setId("12345");
        idp.setName("some-name");
        idp.setOriginKey("some-origin");
        idp.setAliasZid(null);
        idp.setAliasId(null);
        idp.setActive(true);
        idp.setIdentityZoneId(null);
        final OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setIssuer("issuer");
        idp.setConfig(config);

        assertThat(idp).hasToString("IdentityProvider{id='12345', identityZoneId=null, originKey='some-origin', name='some-name', type='oidc1.0', active=true, aliasId=null, aliasZid=null}");
    }

    @Test
    void testEqualsAndHashCode() {
        final String customZoneId = "custom-zone";
        final String aliasIdpId = "id-of-alias-idp";

        final IdentityProvider<OIDCIdentityProviderDefinition> idp1 = new IdentityProvider<>();
        idp1.setId("12345");
        idp1.setName("some-name");
        idp1.setOriginKey("some-origin");
        idp1.setAliasZid(customZoneId);
        idp1.setAliasId(aliasIdpId);
        idp1.setActive(true);
        idp1.setIdentityZoneId(UAA);
        final OIDCIdentityProviderDefinition config1 = new OIDCIdentityProviderDefinition();
        config1.setIssuer("issuer");
        config1.setAuthMethod("none");
        idp1.setConfig(config1);

        final IdentityProvider<OIDCIdentityProviderDefinition> idp2 = new IdentityProvider<>();
        idp2.setId("12345");
        idp2.setName("some-name");
        idp2.setOriginKey("some-origin");
        idp2.setAliasZid(customZoneId);
        idp2.setAliasId(aliasIdpId);
        idp2.setActive(true);
        idp2.setIdentityZoneId(UAA);
        final OIDCIdentityProviderDefinition config2 = new OIDCIdentityProviderDefinition();
        config2.setIssuer("issuer");
        config2.setAuthMethod("none");
        idp2.setConfig(config2);

        idp2.setCreated(idp1.getCreated());
        idp2.setLastModified(idp1.getLastModified());

        // initially, the tow IdPs should be equal
        assertThat(idp1.equals(idp2)).isTrue();
        assertThat(idp1).hasSameHashCodeAs(idp2);

        // remove aliasZid
        idp2.setAliasZid(null);
        assertThat(idp1.equals(idp2)).isFalse();
        assertThat(idp2.equals(idp1)).isFalse();
        idp2.setAliasZid(customZoneId);

        // remove aliasId
        idp2.setAliasId(null);
        assertThat(idp1.equals(idp2)).isFalse();
        assertThat(idp2.equals(idp1)).isFalse();
    }

    @Test
    void testGetAliasDescription() {
        final String customZoneId = "custom-zone";
        final String aliasIdpId = "id-of-alias-idp";

        final IdentityProvider<OIDCIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setId("12345");
        idp.setName("some-name");
        idp.setOriginKey("some-origin");
        idp.setAliasZid(customZoneId);
        idp.setAliasId(aliasIdpId);
        idp.setActive(true);
        idp.setIdentityZoneId(UAA);

        assertThat(idp.getAliasDescription()).isEqualTo(
                "IdentityProvider[id='12345',zid='uaa',aliasId='id-of-alias-idp',aliasZid='custom-zone']"
        );
    }
}