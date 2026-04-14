package org.cloudfoundry.identity.uaa.provider.saml;

import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

/**
 * OpenSAML 5 compatible replacement for Spring Security's {@link OpenSamlMetadataResolver}.
 * <p>
 * Spring Security's {@code OpenSamlMetadataResolver} uses the OpenSAML 4 internal class
 * {@code net.shibboleth.utilities.java.support.xml.SerializeSupport} which is not present
 * when using OpenSAML 5. This implementation uses the OpenSAML 5 equivalent
 * {@code net.shibboleth.shared.xml.SerializeSupport} directly.
 */
public final class OpenSaml5MetadataResolver implements Saml2MetadataResolver {

    private Consumer<OpenSamlMetadataResolver.EntityDescriptorParameters> entityDescriptorCustomizer = (parameters) -> {
    };

    public OpenSaml5MetadataResolver() {
    }

    @Override
    public String resolve(RelyingPartyRegistration relyingPartyRegistration) {
        EntityDescriptor entityDescriptor = buildEntityDescriptor(relyingPartyRegistration);
        return serialize(entityDescriptor);
    }

    /**
     * Set a {@link Consumer} for modifying the OpenSAML {@link EntityDescriptor}.
     */
    public void setEntityDescriptorCustomizer(Consumer<OpenSamlMetadataResolver.EntityDescriptorParameters> entityDescriptorCustomizer) {
        Assert.notNull(entityDescriptorCustomizer, "entityDescriptorCustomizer cannot be null");
        this.entityDescriptorCustomizer = entityDescriptorCustomizer;
    }

    private EntityDescriptor buildEntityDescriptor(RelyingPartyRegistration registration) {
        EntityDescriptor entityDescriptor = build(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entityDescriptor.setEntityID(registration.getEntityId());
        SPSSODescriptor spSsoDescriptor = buildSpSsoDescriptor(registration);
        entityDescriptor.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME).add(spSsoDescriptor);
        this.entityDescriptorCustomizer.accept(
                new OpenSamlMetadataResolver.EntityDescriptorParameters(entityDescriptor, registration));
        return entityDescriptor;
    }

    private SPSSODescriptor buildSpSsoDescriptor(RelyingPartyRegistration registration) {
        SPSSODescriptor spSsoDescriptor = build(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        spSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        spSsoDescriptor.getKeyDescriptors()
                .addAll(buildKeys(registration.getSigningX509Credentials(), UsageType.SIGNING));
        spSsoDescriptor.getKeyDescriptors()
                .addAll(buildKeys(registration.getDecryptionX509Credentials(), UsageType.ENCRYPTION));
        spSsoDescriptor.getAssertionConsumerServices().add(buildAssertionConsumerService(registration));
        if (registration.getSingleLogoutServiceLocation() != null) {
            for (Saml2MessageBinding binding : registration.getSingleLogoutServiceBindings()) {
                spSsoDescriptor.getSingleLogoutServices().add(buildSingleLogoutService(registration, binding));
            }
        }
        if (registration.getNameIdFormat() != null) {
            spSsoDescriptor.getNameIDFormats().add(buildNameIDFormat(registration));
        }
        return spSsoDescriptor;
    }

    private List<KeyDescriptor> buildKeys(Collection<Saml2X509Credential> credentials, UsageType usageType) {
        List<KeyDescriptor> list = new ArrayList<>();
        for (Saml2X509Credential credential : credentials) {
            list.add(buildKeyDescriptor(usageType, credential.getCertificate()));
        }
        return list;
    }

    private KeyDescriptor buildKeyDescriptor(UsageType usageType, java.security.cert.X509Certificate certificate) {
        KeyDescriptor keyDescriptor = build(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        KeyInfo keyInfo = build(KeyInfo.DEFAULT_ELEMENT_NAME);
        X509Certificate x509Certificate = build(X509Certificate.DEFAULT_ELEMENT_NAME);
        X509Data x509Data = build(X509Data.DEFAULT_ELEMENT_NAME);
        try {
            x509Certificate.setValue(new String(Base64.getEncoder().encode(certificate.getEncoded())));
        } catch (CertificateEncodingException ex) {
            throw new Saml2Exception("Cannot encode certificate " + certificate);
        }
        x509Data.getX509Certificates().add(x509Certificate);
        keyInfo.getX509Datas().add(x509Data);
        keyDescriptor.setUse(usageType);
        keyDescriptor.setKeyInfo(keyInfo);
        return keyDescriptor;
    }

    private AssertionConsumerService buildAssertionConsumerService(RelyingPartyRegistration registration) {
        AssertionConsumerService acs = build(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        acs.setLocation(registration.getAssertionConsumerServiceLocation());
        acs.setBinding(registration.getAssertionConsumerServiceBinding().getUrn());
        acs.setIndex(1);
        return acs;
    }

    private SingleLogoutService buildSingleLogoutService(RelyingPartyRegistration registration,
            Saml2MessageBinding binding) {
        SingleLogoutService slo = build(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        slo.setLocation(registration.getSingleLogoutServiceLocation());
        slo.setResponseLocation(registration.getSingleLogoutServiceResponseLocation());
        slo.setBinding(binding.getUrn());
        return slo;
    }

    private NameIDFormat buildNameIDFormat(RelyingPartyRegistration registration) {
        NameIDFormat nameIdFormat = build(NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIdFormat.setURI(registration.getNameIdFormat());
        return nameIdFormat;
    }

    private String serialize(XMLObject xmlObject) {
        try {
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xmlObject);
            if (marshaller == null) {
                throw new Saml2Exception("No marshaller found for " + xmlObject.getClass().getName());
            }
            Element element = marshaller.marshall(xmlObject);
            return SerializeSupport.prettyPrintXML(element);
        } catch (MarshallingException ex) {
            throw new Saml2Exception("Failed to serialize metadata", ex);
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T build(QName elementName) {
        return (T) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(elementName)
                .buildObject(elementName);
    }
}

