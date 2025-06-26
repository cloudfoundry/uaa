package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.SAMLMetadataSignatureSigningParametersResolver;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureSigningParametersResolver;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;

import javax.xml.namespace.QName;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
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
@Slf4j
@Value
public class SamlMetadataEntityDescriptorCustomizer implements Consumer<OpenSamlMetadataResolver.EntityDescriptorParameters> {
    private static final Set<String> NAME_ID_FORMATS = new HashSet<>();
    private static final String URI_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:URI";
    private static final UnaryOperator<String> assertionConsumerServiceLocationMutationFunction = o -> o.replace("/saml/SSO/alias/", "/oauth/token/alias/");

    static {
        NAME_ID_FORMATS.add(NAMEID_FORMAT_EMAIL);
        NAME_ID_FORMATS.add(NAMEID_FORMAT_TRANSIENT);
        NAME_ID_FORMATS.add(NAMEID_FORMAT_PERSISTENT);
        NAME_ID_FORMATS.add(NAMEID_FORMAT_UNSPECIFIED);
        NAME_ID_FORMATS.add(NAMEID_FORMAT_X509SUBJECT);
    }

    IdentityZoneManager identityZoneManager;
    SignatureAlgorithm signatureAlgorithm;
    boolean signMetaData;

    @Override
    public void accept(OpenSamlMetadataResolver.EntityDescriptorParameters entityDescriptorParameters) {
        SamlConfig samlConfig = identityZoneManager.getCurrentIdentityZone().getConfig().getSamlConfig();

        EntityDescriptor entityDescriptor = entityDescriptorParameters.getEntityDescriptor();
        String entityID = escapeToNCName(entityDescriptor.getEntityID());
        entityDescriptor.setID(entityID);
        updateSpSsoDescriptor(entityDescriptor, samlConfig);

        // Signature has to be last, as it will sign the whole entity descriptor
        if (signMetaData && signatureAlgorithm != null) {
            signMetadata(entityDescriptorParameters);
        }
    }

    private String escapeToNCName(String id) {
        if (id == null || id.isEmpty()) {
            id = "_";
        }

        // Ensure the ID starts with a letter or underscore
        if (!Character.isLetter(id.charAt(0)) && id.charAt(0) != '_') {
            id = "_" + id;
        }

        // Replace invalid characters with underscores
        return id.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private void updateSpSsoDescriptor(EntityDescriptor entityDescriptor, SamlConfig samlConfig) {
        SPSSODescriptor spSsoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        spSsoDescriptor.setWantAssertionsSigned(samlConfig.isWantAssertionSigned());
        spSsoDescriptor.setAuthnRequestsSigned(samlConfig.isRequestSigned());
        updateNameIdFormats(spSsoDescriptor);
        updateAssertionConsumerServices(spSsoDescriptor);
    }

    /**
     * Update the assertion consumer services.
     * The first existing assertion consumer service is used as the default,
     * and the second is added for the oauth token endpoint.
     *
     * @param spSsoDescriptor the SP SSO descriptor to update
     */
    private void updateAssertionConsumerServices(SPSSODescriptor spSsoDescriptor) {
        List<AssertionConsumerService> assertionConsumerServices = spSsoDescriptor.getAssertionConsumerServices();

        AssertionConsumerService existingService = assertionConsumerServices.getFirst();
        existingService.setIndex(0);
        existingService.setIsDefault(true);
        String existingUrl = existingService.getLocation();

        AssertionConsumerService additionalService = build(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        additionalService.setBinding(URI_BINDING);
        additionalService.setLocation(assertionConsumerServiceLocationMutationFunction.apply(existingUrl));
        additionalService.setIndex(1);
        assertionConsumerServices.add(additionalService);
    }

    /**
     * Add a signature element to the entity descriptor.
     * The signature contains the active key's certificate.
     *
     * @param entityDescriptorParameters the entity descriptor parameters
     */
    private void signMetadata(OpenSamlMetadataResolver.EntityDescriptorParameters entityDescriptorParameters) {

        EntityDescriptor entityDescriptor = entityDescriptorParameters.getEntityDescriptor();
        RelyingPartyRegistration registration = entityDescriptorParameters.getRelyingPartyRegistration();
        SignatureSigningParameters parameters = resolveSigningParameters(registration);
        try {
            SignatureSupport.signObject(entityDescriptor, parameters);
        } catch (SecurityException | SignatureException | MarshallingException e) {
            log.error("Error signing entity descriptor", e);
        }
    }

    private void updateNameIdFormats(SPSSODescriptor spSsoDescriptor) {
        // OpenSamlMetadataResolver adds the item from the relyingPartyRegistration,
        // Create a set to be used to ignore adding duplicates
        Set<String> existingNameIDFormats = spSsoDescriptor.getNameIDFormats().stream().map(NameIDFormat::getURI).collect(Collectors.toSet());
        spSsoDescriptor.getNameIDFormats().addAll(NAME_ID_FORMATS.stream().filter(Predicate.not(existingNameIDFormats::contains)).map(this::buildNameIDFormat).collect(Collectors.toSet()));
    }

    private NameIDFormat buildNameIDFormat(String value) {
        NameIDFormat nameIdFormat = build(NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIdFormat.setURI(value);
        return nameIdFormat;
    }

    private <T> T build(QName elementName) {
        XMLObjectBuilder<?> builder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(elementName);
        if (builder == null) {
            throw new Saml2Exception("Unable to resolve Builder for " + elementName);
        }
        //noinspection unchecked
        return (T) builder.buildObject(elementName);
    }

    private SignatureSigningParameters resolveSigningParameters(RelyingPartyRegistration relyingPartyRegistration) {

        List<Credential> credentials = resolveSigningCredentials(relyingPartyRegistration);
        SignatureSigningParametersResolver resolver = new SAMLMetadataSignatureSigningParametersResolver();
        BasicSignatureSigningConfiguration signingConfiguration = new BasicSignatureSigningConfiguration();
        signingConfiguration.setSigningCredentials(credentials);
        signingConfiguration.setSignatureAlgorithms(List.of(signatureAlgorithm.getSignatureAlgorithmURI()));
        signingConfiguration.setSignatureReferenceDigestMethods(List.of(signatureAlgorithm.getDigestAlgorithmURI()));
        signingConfiguration.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signingConfiguration.setKeyInfoGeneratorManager(buildSignatureKeyInfoGeneratorManager());

        CriteriaSet criteria = new CriteriaSet();
        criteria.add(new SignatureSigningConfigurationCriterion(signingConfiguration));
        try {
            SignatureSigningParameters parameters = resolver.resolveSingle(criteria);
            Assert.notNull(parameters, "Failed to resolve any signing credential");
            return parameters;
        } catch (Exception ex) {
            throw new Saml2Exception(ex);
        }
    }

    private static List<Credential> resolveSigningCredentials(RelyingPartyRegistration relyingPartyRegistration) {
        List<Credential> credentials = new ArrayList<>();
        for (Saml2X509Credential x509Credential : relyingPartyRegistration.getSigningX509Credentials()) {
            java.security.cert.X509Certificate certificate = x509Credential.getCertificate();
            PrivateKey privateKey = x509Credential.getPrivateKey();
            BasicCredential credential = CredentialSupport.getSimpleCredential(certificate, privateKey);
            credential.setEntityId(relyingPartyRegistration.getEntityId());
            credential.setUsageType(UsageType.SIGNING);
            credentials.add(credential);
        }
        return credentials;
    }

    private static NamedKeyInfoGeneratorManager buildSignatureKeyInfoGeneratorManager() {
        final NamedKeyInfoGeneratorManager namedManager = new NamedKeyInfoGeneratorManager();

        namedManager.setUseDefaultManager(true);
        final KeyInfoGeneratorManager defaultManager = namedManager.getDefaultManager();

        // Generator for X509Credentials
        final X509KeyInfoGeneratorFactory x509Factory = new X509KeyInfoGeneratorFactory();
        x509Factory.setEmitEntityCertificate(true);
        x509Factory.setEmitEntityCertificateChain(true);

        defaultManager.registerFactory(x509Factory);

        return namedManager;
    }
}
