package org.cloudfoundry.identity.uaa.provider;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UNKNOWN;

class IdentityProviderTest {

    @Test
    void toStringShouldContainAliasProperties() {
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
    void toStringAliasPropertiesAndIdzIdNull() {
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
    void equalsAndHashCode() {
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
        assertThat(idp1).isEqualTo(idp2)
                .hasSameHashCodeAs(idp2);

        // remove aliasZid
        idp2.setAliasZid(null);
        assertThat(idp1).isNotEqualTo(idp2);
        assertThat(idp2).isNotEqualTo(idp1);
        idp2.setAliasZid(customZoneId);

        // remove aliasId
        idp2.setAliasId(null);
        assertThat(idp1).isNotEqualTo(idp2);
        assertThat(idp2).isNotEqualTo(idp1);
    }

    @Test
    void getAliasDescription() {
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

    @Test
    void setConfigSamlType() {
        final IdentityProvider<SamlIdentityProviderDefinition> idp = new IdentityProvider<>();
        final SamlIdentityProviderDefinition config = new SamlIdentityProviderDefinition();
        idp.setConfig(config);

        assertThat(idp).returns(SAML, IdentityProvider::getType);
    }

    @Test
    void setConfigUAAType() {
        final IdentityProvider<UaaIdentityProviderDefinition> idp = new IdentityProvider<>();
        final UaaIdentityProviderDefinition config = new UaaIdentityProviderDefinition();
        idp.setConfig(config);

        assertThat(idp).returns(UAA, IdentityProvider::getType);
    }

    @Test
    void setConfigOauth2Type() {
        final IdentityProvider<RawExternalOAuthIdentityProviderDefinition> idp = new IdentityProvider<>();
        final RawExternalOAuthIdentityProviderDefinition config = new RawExternalOAuthIdentityProviderDefinition();
        idp.setConfig(config);

        assertThat(idp).returns(OAUTH20, IdentityProvider::getType);
    }

    @Test
    void setConfigOidcType() {
        final IdentityProvider<OIDCIdentityProviderDefinition> idp = new IdentityProvider<>();
        final OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        idp.setConfig(config);

        assertThat(idp).returns(OIDC10, IdentityProvider::getType);
    }

    @Test
    void setConfigLdapType() {
        final IdentityProvider<LdapIdentityProviderDefinition> idp = new IdentityProvider<>();
        final LdapIdentityProviderDefinition config = new LdapIdentityProviderDefinition();
        idp.setConfig(config);

        assertThat(idp).returns(LDAP, IdentityProvider::getType);
    }

    @Test
    void setConfigKeystoneType() {
        final IdentityProvider<KeystoneIdentityProviderDefinition> idp = new IdentityProvider<>();
        final KeystoneIdentityProviderDefinition config = new KeystoneIdentityProviderDefinition();
        idp.setConfig(config);

        assertThat(idp).returns(KEYSTONE, IdentityProvider::getType);
    }

    @Test
    void setConfigUnknownType() {
        final IdentityProvider<AbstractIdentityProviderDefinition> idp = new IdentityProvider<>();
        final AbstractIdentityProviderDefinition config = new AbstractIdentityProviderDefinition();
        idp.setConfig(config);

        assertThat(idp).returns(UNKNOWN, IdentityProvider::getType);
    }

    @Test
    void setConfigNull() {
        final IdentityProvider<AbstractIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setConfig(null);

        assertThat(idp)
                .returns(UNKNOWN, IdentityProvider::getType)
                .returns(null, IdentityProvider::getConfig);
    }
}
