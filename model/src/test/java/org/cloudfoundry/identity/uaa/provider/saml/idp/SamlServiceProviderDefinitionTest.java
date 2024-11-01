package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SamlServiceProviderDefinitionTest {

    private static final String METADATA_URL_LOCATION = "https://www.cloudfoundry.org/";
    private static final String VALUE = "value";

    @Test
    void getType_validXml() {
        var def = new SamlServiceProviderDefinition();

        def.setMetaDataLocation("""
                 <?xml version="1.0" encoding="UTF-8"?>
                 <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="cloudfoundry-saml-login"
                                      entityID="cloudfoundry-saml-login" />
                """);
        assertThat(def.getType()).isEqualTo(SamlServiceProviderDefinition.MetadataLocation.DATA);
    }

    @Test
    void getType_invalidXml() {
        var def = new SamlServiceProviderDefinition();

        def.setMetaDataLocation("<md:EntityDescriptor>");
        assertThat(def.getType()).isEqualTo(SamlServiceProviderDefinition.MetadataLocation.UNKNOWN);
    }

    @Test
    void getType_doctype() {
        var def = new SamlServiceProviderDefinition();
        def.setMetaDataLocation("""
            <?xml version="1.0" encoding="UTF-8"?>
            <!doctype html>
            """);
        assertThat(def.getType()).isEqualTo(SamlServiceProviderDefinition.MetadataLocation.UNKNOWN);
    }

    @Test
    void getType_Url() {
        var def = new SamlServiceProviderDefinition();
        def.setMetaDataLocation(METADATA_URL_LOCATION);
        assertThat(def.getType()).isEqualTo(SamlServiceProviderDefinition.MetadataLocation.URL);
    }

    @Test
    void metaDataLocation() {
        var def = new SamlServiceProviderDefinition();
        def.setMetaDataLocation(METADATA_URL_LOCATION);

        assertThat(def.getMetaDataLocation()).isEqualTo(METADATA_URL_LOCATION);
    }

    @Test
    void nameID() {
        var def = new SamlServiceProviderDefinition();
        def.setNameID(VALUE);
        assertThat(def.getNameID()).isEqualTo(VALUE);
    }

    @Test
    void singleSignOnServiceIndex() {
        var def = new SamlServiceProviderDefinition();
        def.setSingleSignOnServiceIndex(2);
        assertThat(def.getSingleSignOnServiceIndex()).isEqualTo(2);
    }

    @Test
    void metadataTrustCheck() {
        var def = new SamlServiceProviderDefinition();
        assertThat(def.isMetadataTrustCheck()).isFalse();
        def.setMetadataTrustCheck(true);
        assertThat(def.isMetadataTrustCheck()).isTrue();
    }

    @Test
    void skipSslValidation() {
        var def = new SamlServiceProviderDefinition();
        assertThat(def.isSkipSslValidation()).isFalse();
        def.setSkipSslValidation(true);
        assertThat(def.isSkipSslValidation()).isTrue();
    }

    @Test
    void enableIdpInitiatedSso() {
        var def = new SamlServiceProviderDefinition();
        assertThat(def.isEnableIdpInitiatedSso()).isFalse();
        def.setEnableIdpInitiatedSso(true);
        assertThat(def.isEnableIdpInitiatedSso()).isTrue();
    }

    @Test
    void attributeMappings() {
        var def = new SamlServiceProviderDefinition();
        assertThat(def.getAttributeMappings()).isEmpty();
        def.setAttributeMappings(Map.of("k1", "v1"));
        assertThat(def.getAttributeMappings()).hasSize(1).containsEntry("k1", "v1");
    }

    @Test
    void staticCustomAttributes() {
        var def = new SamlServiceProviderDefinition();
        assertThat(def.getStaticCustomAttributes()).isEmpty();
        def.setStaticCustomAttributes(Map.of("k1", "v1"));
        assertThat(def.getStaticCustomAttributes()).hasSize(1).containsEntry("k1", "v1");
    }

    @Test
    void testHashCode() {
        var def1 = new SamlServiceProviderDefinition();
        var def2 = new SamlServiceProviderDefinition();
        assertThat(def1).hasSameHashCodeAs(def2);
    }

    @Test
    void equals() {
        var def1 = new SamlServiceProviderDefinition();
        var def2 = new SamlServiceProviderDefinition();
        assertThat(def1).isEqualTo(def2);

        def1.setNameID(VALUE);
        assertThat(def1).isNotEqualTo(def2);
    }

    @Test
    void testToString() {
        var def1 = new SamlServiceProviderDefinition();
        def1.setNameID(VALUE);
        assertThat(def1).hasToString("SamlServiceProviderDefinition{metaDataLocation='null', nameID='value', singleSignOnServiceIndex=0, metadataTrustCheck=false, skipSslValidation=false, attributeMappings={}}");
    }

    @Test
    void builder() {
        var def1 = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(METADATA_URL_LOCATION)
                .setNameID(VALUE)
                .setSingleSignOnServiceIndex(3)
                .setMetadataTrustCheck(true)
                .setEnableIdpInitiatedSso(true)
                .build();

        assertThat(def1)
                .returns( METADATA_URL_LOCATION, SamlServiceProviderDefinition::getMetaDataLocation)
                .returns( VALUE, SamlServiceProviderDefinition::getNameID)
                .returns( 3, SamlServiceProviderDefinition::getSingleSignOnServiceIndex)
                .returns( true, SamlServiceProviderDefinition::isMetadataTrustCheck)
                .returns( true, SamlServiceProviderDefinition::isSkipSslValidation)
                .returns( true, SamlServiceProviderDefinition::isEnableIdpInitiatedSso);

    }

    @Test
    void testClone() {
        var def1 = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(METADATA_URL_LOCATION)
                .setNameID(VALUE)
                .setSingleSignOnServiceIndex(3)
                .setMetadataTrustCheck(true)
                .setEnableIdpInitiatedSso(true)
                .build();

        assertThat(def1.clone()).isEqualTo(def1);
    }
}
