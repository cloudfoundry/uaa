package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Value;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.ContentReference;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_EMAIL;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_PERSISTENT;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_TRANSIENT;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_UNSPECIFIED;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_X509SUBJECT;

/**
 * This class is used to customize the EntityDescriptor used in the Metadata call,
 * it is called as part of the {@link OpenSamlMetadataResolver} after basic creation is completed.
 */
@Value
public class SamlMetadataEntityDescriptorCustomizer implements Consumer<OpenSamlMetadataResolver.EntityDescriptorParameters> {
    private static final Set<String> NAME_ID_FORMATS = new HashSet<>();

    static {
        NAME_ID_FORMATS.add(NAMEID_FORMAT_EMAIL);
        NAME_ID_FORMATS.add(NAMEID_FORMAT_TRANSIENT);
        NAME_ID_FORMATS.add(NAMEID_FORMAT_PERSISTENT);
        NAME_ID_FORMATS.add(NAMEID_FORMAT_UNSPECIFIED);
        NAME_ID_FORMATS.add(NAMEID_FORMAT_X509SUBJECT);
    }

    IdentityZoneManager identityZoneManager;

    @Override
    public void accept(OpenSamlMetadataResolver.EntityDescriptorParameters entityDescriptorParameters) {
        SamlConfig samlConfig = identityZoneManager.getCurrentIdentityZone().getConfig().getSamlConfig();

        EntityDescriptor entityDescriptor = entityDescriptorParameters.getEntityDescriptor();
        entityDescriptor.setID(entityDescriptor.getEntityID());
        addSignatureElement(entityDescriptor, samlConfig);

        SPSSODescriptor spSsoDescriptor = updateSpSsoDescriptor(entityDescriptor, samlConfig);

        updateNameIdFormats(spSsoDescriptor);
    }

    private static SPSSODescriptor updateSpSsoDescriptor(EntityDescriptor entityDescriptor, SamlConfig samlConfig) {
        SPSSODescriptor spSsoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        spSsoDescriptor.setWantAssertionsSigned(samlConfig.isWantAssertionSigned());
        spSsoDescriptor.setAuthnRequestsSigned(samlConfig.isRequestSigned());

        return spSsoDescriptor;
    }

    /**
     * Add a signature element to the entity descriptor.
     * The signature contains the active key's certificate.
     *
     * @param entityDescriptor
     * @param samlConfig
     */
    private static void addSignatureElement(EntityDescriptor entityDescriptor, SamlConfig samlConfig) {
        Signature signature = entityDescriptor.getSignature();
        if (signature == null) {
            signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
            entityDescriptor.setSignature(signature);
        }
        signature.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        signature.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
        List<ContentReference> contentReferences = signature.getContentReferences();
        // TODO: ds:DigestValue is not set
        // TODO: ds:SignatureValue is not set

        KeyInfo keyInfo = signature.getKeyInfo();
        if (keyInfo == null) {
            keyInfo = (KeyInfo) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME).buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            signature.setKeyInfo(keyInfo);
        }

        List<X509Data> x509Datas = keyInfo.getX509Datas();
        if (x509Datas.isEmpty()) {
            x509Datas.add((X509Data) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(X509Data.DEFAULT_ELEMENT_NAME).buildObject(X509Data.DEFAULT_ELEMENT_NAME));
        }
        X509Data x509Data = x509Datas.get(0);
        List<X509Certificate> x509Certificates = x509Data.getX509Certificates();

        SamlKey activeKey = samlConfig.getActiveKey();
        if (activeKey != null) {
            X509Certificate x509 = (X509Certificate) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME).buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);
            x509.setValue(bareCertData(activeKey.getCertificate()));
            x509Certificates.add(x509);
        }
    }

    private static String bareCertData(String cert) {
        return cert.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }

    private void updateNameIdFormats(SPSSODescriptor spSsoDescriptor) {
        // TODO: dedupe the name id formats
        spSsoDescriptor.getNameIDFormats().addAll(NAME_ID_FORMATS.stream().map(this::buildNameIDFormat).collect(Collectors.toSet()));
    }

    private NameIDFormat buildNameIDFormat(String value) {
        XMLObjectBuilder<NameIDFormat> builder = (XMLObjectBuilder<NameIDFormat>) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);
        if (builder == null) {
            throw new Saml2Exception("Unable to resolve Builder for " + NameIDFormat.DEFAULT_ELEMENT_NAME);
        }

        NameIDFormat nameIdFormat = builder.buildObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIdFormat.setFormat(value); // nosonar
        return nameIdFormat;
    }
}
