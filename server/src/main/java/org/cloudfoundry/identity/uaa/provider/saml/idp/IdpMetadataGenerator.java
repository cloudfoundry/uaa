/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.common.impl.ExtensionsBuilder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.samlext.idpdisco.DiscoveryResponse;
import org.opensaml.util.URLBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.util.SAMLUtil;

import javax.xml.namespace.QName;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * The class is responsible for generating the metadata that describes the identity provider in the current deployment
 * environment. All the URLs in the metadata derive from information provided by the ServletContext.
 *
 * This code for this class is based on org.springframework.security.saml.metadata.MetadataGenerator.
 */
public class IdpMetadataGenerator {

    private String id;
    private String entityId;
    private String entityBaseURL;

    private boolean wantAuthnRequestSigned = true;

    /**
     * Index of the assertion consumer endpoint marked as default.
     */
    private int assertionConsumerIndex = 0;

    /**
     * Extended metadata with details on metadata generation.
     */
    private IdpExtendedMetadata extendedMetadata;

    // List of case-insensitive alias terms
    private static TreeMap<String, String> aliases = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);

    static {
        aliases.put(SAMLConstants.SAML2_POST_BINDING_URI, SAMLConstants.SAML2_POST_BINDING_URI);
        aliases.put("post", SAMLConstants.SAML2_POST_BINDING_URI);
        aliases.put("http-post", SAMLConstants.SAML2_POST_BINDING_URI);
        aliases.put(SAMLConstants.SAML2_PAOS_BINDING_URI, SAMLConstants.SAML2_PAOS_BINDING_URI);
        aliases.put("paos", SAMLConstants.SAML2_PAOS_BINDING_URI);
        aliases.put(SAMLConstants.SAML2_REDIRECT_BINDING_URI, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        aliases.put("redirect", SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        aliases.put("http-redirect", SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        aliases.put(SAMLConstants.SAML2_SOAP11_BINDING_URI, SAMLConstants.SAML2_SOAP11_BINDING_URI);
        aliases.put("soap", SAMLConstants.SAML2_SOAP11_BINDING_URI);
        aliases.put(NameIDType.EMAIL, NameIDType.EMAIL);
        aliases.put("email", NameIDType.EMAIL);
        aliases.put(NameIDType.TRANSIENT, NameIDType.TRANSIENT);
        aliases.put("transient", NameIDType.TRANSIENT);
        aliases.put(NameIDType.PERSISTENT, NameIDType.PERSISTENT);
        aliases.put("persistent", NameIDType.PERSISTENT);
        aliases.put(NameIDType.UNSPECIFIED, NameIDType.UNSPECIFIED);
        aliases.put("unspecified", NameIDType.UNSPECIFIED);
        aliases.put(NameIDType.X509_SUBJECT, NameIDType.X509_SUBJECT);
        aliases.put("x509_subject", NameIDType.X509_SUBJECT);
    }

    /**
     * Bindings for single sign-on
     */
    private Collection<String> bindingsSSO = Arrays.asList("post", "redirect");

    /**
     * Bindings for single sign-on holder of key
     */
    private Collection<String> bindingsHoKSSO = Collections.emptyList();

    /**
     * Bindings for single logout
     */
    private Collection<String> bindingsSLO = Collections.emptyList();

    /**
     * Flag indicates whether to include extension with discovery endpoints in metadata.
     */
    private boolean includeDiscoveryExtension;

    /**
     * NameIDs to be included in generated metadata.
     */
    private Collection<String> nameID = null;

    /**
     * Default set of NameIDs included in metadata.
     */
    public static final Collection<String> defaultNameID = Arrays.asList(NameIDType.EMAIL, NameIDType.TRANSIENT,
            NameIDType.PERSISTENT, NameIDType.UNSPECIFIED, NameIDType.X509_SUBJECT);

    protected XMLObjectBuilderFactory builderFactory;

    /**
     * Source of certificates.
     */
    protected KeyManager keyManager;

    /**
     * Filters for loading of paths.
     */
    protected SAMLProcessingFilter samlWebSSOFilter;
    protected SAMLWebSSOHoKProcessingFilter samlWebSSOHoKFilter;
    protected SAMLLogoutProcessingFilter samlLogoutProcessingFilter;
    protected SAMLEntryPoint samlEntryPoint;
    protected SAMLDiscovery samlDiscovery;

    /**
     * Class logger.
     */
    protected final static Logger log = LoggerFactory.getLogger(IdpMetadataGenerator.class);

    /**
     * Default constructor.
     */
    public IdpMetadataGenerator() {
        this.builderFactory = Configuration.getBuilderFactory();
    }

    public EntityDescriptor generateMetadata() {

        boolean wantAuthnRequestSigned = isWantAuthnRequestSigned();

        Collection<String> includedNameID = getNameID();

        String entityId = getEntityId();
        String entityBaseURL = getEntityBaseURL();
        String entityAlias = getEntityAlias();

        validateRequiredAttributes(entityId, entityBaseURL);

        if (id == null) {
            // Use entityID cleaned as NCName for ID in case no value is provided
            id = SAMLUtil.getNCNameString(entityId);
        }

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory
                .getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = builder.buildObject();
        if (id != null) {
            descriptor.setID(id);
        }
        descriptor.setEntityID(entityId);

        IDPSSODescriptor ssoDescriptor = buildIDPSSODescriptor(entityBaseURL, entityAlias, wantAuthnRequestSigned,
                includedNameID);
        if (ssoDescriptor != null) {
            descriptor.getRoleDescriptors().add(ssoDescriptor);
        }

        return descriptor;
    }

    protected void validateRequiredAttributes(String entityId, String entityBaseURL) {
        if (entityId == null || entityBaseURL == null) {
            throw new RuntimeException("Required attributes entityId or entityBaseURL weren't set");
        }
    }

    protected KeyInfo getServerKeyInfo(String alias) {
        Credential serverCredential = keyManager.getCredential(alias);
        if (serverCredential == null) {
            throw new RuntimeException("Key for alias " + alias + " not found");
        } else if (serverCredential.getPrivateKey() == null) {
            throw new RuntimeException("Key with alias " + alias + " doesn't have a private key");
        }
        return generateKeyInfoForCredential(serverCredential);
    }

    /**
     * Generates extended metadata. Default extendedMetadata object is cloned if present and used for defaults. The
     * following properties are always overriden from the properties of this bean: discoveryUrl, discoveryResponseUrl,
     * signingKey, encryptionKey, entityAlias and tlsKey. Property local of the generated metadata is always set to
     * true.
     *
     * @return generated extended metadata
     */
    public IdpExtendedMetadata generateExtendedMetadata() {

        IdpExtendedMetadata metadata;

        if (extendedMetadata != null) {
            metadata = extendedMetadata.clone();
        } else {
            metadata = new IdpExtendedMetadata();
        }

        String entityBaseURL = getEntityBaseURL();
        String entityAlias = getEntityAlias();

        if (isIncludeDiscovery()) {
            metadata.setIdpDiscoveryURL(getDiscoveryURL(entityBaseURL, entityAlias));
            metadata.setIdpDiscoveryResponseURL(getDiscoveryResponseURL(entityBaseURL, entityAlias));
        } else {
            metadata.setIdpDiscoveryURL(null);
            metadata.setIdpDiscoveryResponseURL(null);
        }

        metadata.setLocal(true);
        metadata.setAssertionTimeToLiveSeconds(getAssertionTimeToLiveSeconds());
        metadata.setAssertionsSigned(isAssertionsSigned());
        return metadata;

    }

    protected KeyInfo generateKeyInfoForCredential(Credential credential) {
        try {
            String keyInfoGeneratorName = org.springframework.security.saml.SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR;
            if (extendedMetadata != null && extendedMetadata.getKeyInfoGeneratorName() != null) {
                keyInfoGeneratorName = extendedMetadata.getKeyInfoGeneratorName();
            }
            KeyInfoGenerator keyInfoGenerator = SecurityHelper.getKeyInfoGenerator(credential, null,
                    keyInfoGeneratorName);
            return keyInfoGenerator.generate(credential);
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.error("Can't obtain key from the keystore or generate key info for credential: " + credential, e);
            throw new SAMLRuntimeException("Can't obtain key from keystore or generate key info", e);
        }
    }

    protected IDPSSODescriptor buildIDPSSODescriptor(String entityBaseURL, String entityAlias,
            boolean wantAuthnRequestSigned, Collection<String> includedNameID) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<IDPSSODescriptor> builder = (SAMLObjectBuilder<IDPSSODescriptor>) builderFactory
                .getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        IDPSSODescriptor idpDescriptor = builder.buildObject();
        idpDescriptor.setWantAuthnRequestsSigned(wantAuthnRequestSigned);
        idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // Name ID
        idpDescriptor.getNameIDFormats().addAll(getNameIDFormat(includedNameID));

        // Resolve alases
        Collection<String> bindingsSSO = mapAliases(getBindingsSSO());
        Collection<String> bindingsSLO = mapAliases(getBindingsSLO());

        // Assertion consumer MUST NOT be used with HTTP Redirect, Profiles 424, same applies to HoK profile
        for (String binding : bindingsSSO) {
            if (binding.equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                idpDescriptor.getSingleSignOnServices().add(getSingleSignOnService(entityBaseURL, entityAlias,
                        getSAMLWebSSOProcessingFilterPath(), SAMLConstants.SAML2_POST_BINDING_URI));
            }
            if (binding.equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                idpDescriptor.getSingleSignOnServices().add(getSingleSignOnService(entityBaseURL, entityAlias,
                        getSAMLWebSSOProcessingFilterPath(), SAMLConstants.SAML2_REDIRECT_BINDING_URI));
            }
        }

        for (String binding : bindingsSLO) {
            if (binding.equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                idpDescriptor.getSingleLogoutServices()
                        .add(getSingleLogoutService(entityBaseURL, entityAlias, SAMLConstants.SAML2_POST_BINDING_URI));
            }
            if (binding.equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                idpDescriptor.getSingleLogoutServices().add(
                        getSingleLogoutService(entityBaseURL, entityAlias, SAMLConstants.SAML2_REDIRECT_BINDING_URI));
            }
            if (binding.equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
                idpDescriptor.getSingleLogoutServices().add(
                        getSingleLogoutService(entityBaseURL, entityAlias, SAMLConstants.SAML2_SOAP11_BINDING_URI));
            }
        }

        // Build extensions
        Extensions extensions = buildExtensions(entityBaseURL, entityAlias);
        if (extensions != null) {
            idpDescriptor.setExtensions(extensions);
        }

        // Populate key aliases
        String signingKey = getSigningKey();
        String encryptionKey = getEncryptionKey();
        String tlsKey = getTLSKey();

        // Generate key info
        if (signingKey != null) {
            idpDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.SIGNING, getServerKeyInfo(signingKey)));
        } else {
            log.info(
                    "Generating metadata without signing key, KeyStore doesn't contain any default private key, or the signingKey specified in ExtendedMetadata cannot be found");
        }
        if (encryptionKey != null) {
            idpDescriptor.getKeyDescriptors()
                    .add(getKeyDescriptor(UsageType.ENCRYPTION, getServerKeyInfo(encryptionKey)));
        } else {
            log.info(
                    "Generating metadata without encryption key, KeyStore doesn't contain any default private key, or the encryptionKey specified in ExtendedMetadata cannot be found");
        }

        // Include TLS key with unspecified usage in case it differs from the singing and encryption keys
        if (tlsKey != null && !(tlsKey.equals(encryptionKey)) && !(tlsKey.equals(signingKey))) {
            idpDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.UNSPECIFIED, getServerKeyInfo(tlsKey)));
        }

        return idpDescriptor;
    }

    /**
     * Method iterates all values in the input, for each tries to resolve correct alias. When alias value is found, it
     * is entered into the return collection, otherwise warning is logged. Values are returned in order of input with
     * all duplicities removed.
     *
     * @param values
     *            input collection
     * @return result with resolved aliases
     */
    protected Collection<String> mapAliases(Collection<String> values) {
        LinkedHashSet<String> result = new LinkedHashSet<String>();
        for (String value : values) {
            String alias = aliases.get(value);
            if (alias != null) {
                result.add(alias);
            } else {
                log.warn("Unsupported value " + value + " found");
            }
        }
        return result;
    }

    protected Extensions buildExtensions(String entityBaseURL, String entityAlias) {

        boolean include = false;
        Extensions extensions = new ExtensionsBuilder().buildObject();

        // Add discovery
        if (isIncludeDiscoveryExtension()) {
            DiscoveryResponse discoveryService = getDiscoveryService(entityBaseURL, entityAlias);
            extensions.getUnknownXMLObjects().add(discoveryService);
            include = true;
        }

        if (include) {
            return extensions;
        } else {
            return null;
        }

    }

    protected KeyDescriptor getKeyDescriptor(UsageType type, KeyInfo key) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<KeyDescriptor> builder = (SAMLObjectBuilder<KeyDescriptor>) Configuration.getBuilderFactory()
                .getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        KeyDescriptor descriptor = builder.buildObject();
        descriptor.setUse(type);
        descriptor.setKeyInfo(key);
        return descriptor;
    }

    protected Collection<NameIDFormat> getNameIDFormat(Collection<String> includedNameID) {

        // Resolve alases
        includedNameID = mapAliases(includedNameID);
        Collection<NameIDFormat> formats = new LinkedList<NameIDFormat>();
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<NameIDFormat> builder = (SAMLObjectBuilder<NameIDFormat>) builderFactory
                .getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);

        // Populate nameIDs
        for (String nameIDValue : includedNameID) {

            if (nameIDValue.equals(NameIDType.EMAIL)) {
                NameIDFormat nameID = builder.buildObject();
                nameID.setFormat(NameIDType.EMAIL);
                formats.add(nameID);
            }

            if (nameIDValue.equals(NameIDType.TRANSIENT)) {
                NameIDFormat nameID = builder.buildObject();
                nameID.setFormat(NameIDType.TRANSIENT);
                formats.add(nameID);
            }

            if (nameIDValue.equals(NameIDType.PERSISTENT)) {
                NameIDFormat nameID = builder.buildObject();
                nameID.setFormat(NameIDType.PERSISTENT);
                formats.add(nameID);
            }

            if (nameIDValue.equals(NameIDType.UNSPECIFIED)) {
                NameIDFormat nameID = builder.buildObject();
                nameID.setFormat(NameIDType.UNSPECIFIED);
                formats.add(nameID);
            }

            if (nameIDValue.equals(NameIDType.X509_SUBJECT)) {
                NameIDFormat nameID = builder.buildObject();
                nameID.setFormat(NameIDType.X509_SUBJECT);
                formats.add(nameID);
            }

        }

        return formats;

    }

    protected SingleSignOnService getSingleSignOnService(String entityBaseURL, String entityAlias, String filterURL,
            String binding) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<SingleSignOnService> builder = (SAMLObjectBuilder<SingleSignOnService>) builderFactory
                .getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
        SingleSignOnService sso = builder.buildObject();
        sso.setLocation(getServerURL(entityBaseURL, entityAlias, filterURL));
        sso.setBinding(binding);
        return sso;
    }

    protected SingleSignOnService getHoKSingleSignOnService(String entityBaseURL, String entityAlias, String filterURL,
            String binding) {
        SingleSignOnService hokSso = getSingleSignOnService(entityBaseURL, entityAlias, filterURL,
                org.springframework.security.saml.SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI);
        QName consumerName = new QName(org.springframework.security.saml.SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI,
                AuthnRequest.PROTOCOL_BINDING_ATTRIB_NAME, "hoksso");
        hokSso.getUnknownAttributes().put(consumerName, binding);
        return hokSso;
    }

    protected DiscoveryResponse getDiscoveryService(String entityBaseURL, String entityAlias) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<DiscoveryResponse> builder = (SAMLObjectBuilder<DiscoveryResponse>) builderFactory
                .getBuilder(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
        DiscoveryResponse discovery = builder.buildObject(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
        discovery.setBinding(DiscoveryResponse.IDP_DISCO_NS);
        discovery.setLocation(getDiscoveryResponseURL(entityBaseURL, entityAlias));
        return discovery;
    }

    protected SingleLogoutService getSingleLogoutService(String entityBaseURL, String entityAlias, String binding) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<SingleLogoutService> builder = (SAMLObjectBuilder<SingleLogoutService>) builderFactory
                .getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        SingleLogoutService logoutService = builder.buildObject();
        logoutService.setLocation(getServerURL(entityBaseURL, entityAlias, getSAMLLogoutFilterPath()));
        logoutService.setBinding(binding);
        return logoutService;
    }

    /**
     * Creates URL at which the local server is capable of accepting incoming SAML messages.
     *
     * @param entityBaseURL
     *            entity ID
     * @param processingURL
     *            local context at which processing filter is waiting
     * @return URL of local server
     */
    private String getServerURL(String entityBaseURL, String entityAlias, String processingURL) {

        return getServerURL(entityBaseURL, entityAlias, processingURL, null);

    }

    /**
     * Creates URL at which the local server is capable of accepting incoming SAML messages.
     *
     * @param entityBaseURL
     *            entity ID
     * @param processingURL
     *            local context at which processing filter is waiting
     * @param parameters
     *            key - value pairs to be included as query part of the generated url, can be null
     * @return URL of local server
     */
    private String getServerURL(String entityBaseURL, String entityAlias, String processingURL,
            Map<String, String> parameters) {

        StringBuilder result = new StringBuilder();
        result.append(entityBaseURL);
        if (!processingURL.startsWith("/")) {
            result.append("/");
        }
        result.append(processingURL);

        if (entityAlias != null) {
            if (!processingURL.endsWith("/")) {
                result.append("/");
            }
            result.append("alias/");
            result.append(entityAlias);
        }

        String resultString = result.toString();

        if (parameters == null || parameters.size() == 0) {

            return resultString;

        } else {

            // Add parameters
            URLBuilder returnUrlBuilder = new URLBuilder(resultString);
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                returnUrlBuilder.getQueryParams().add(new Pair<String, String>(entry.getKey(), entry.getValue()));
            }
            return returnUrlBuilder.buildURL();

        }

    }

    private String getSAMLWebSSOProcessingFilterPath() {
        if (samlWebSSOFilter != null) {
            return samlWebSSOFilter.getFilterProcessesUrl();
        } else {
            return SAMLProcessingFilter.FILTER_URL;
        }
    }

    private String getSAMLEntryPointPath() {
        if (samlEntryPoint != null) {
            return samlEntryPoint.getFilterProcessesUrl();
        } else {
            return SAMLEntryPoint.FILTER_URL;
        }
    }

    private String getSAMLDiscoveryPath() {
        if (samlDiscovery != null) {
            return samlDiscovery.getFilterProcessesUrl();
        } else {
            return SAMLDiscovery.FILTER_URL;
        }
    }

    private String getSAMLLogoutFilterPath() {
        if (samlLogoutProcessingFilter != null) {
            return samlLogoutProcessingFilter.getFilterProcessesUrl();
        } else {
            return SAMLLogoutProcessingFilter.FILTER_URL;
        }
    }

    @Autowired(required = false)
    @Qualifier("samlWebSSOProcessingFilter")
    public void setSamlWebSSOFilter(SAMLProcessingFilter samlWebSSOFilter) {
        this.samlWebSSOFilter = samlWebSSOFilter;
    }

    @Autowired(required = false)
    @Qualifier("samlWebSSOHoKProcessingFilter")
    public void setSamlWebSSOHoKFilter(SAMLWebSSOHoKProcessingFilter samlWebSSOHoKFilter) {
        this.samlWebSSOHoKFilter = samlWebSSOHoKFilter;
    }

    @Autowired(required = false)
    public void setSamlLogoutProcessingFilter(SAMLLogoutProcessingFilter samlLogoutProcessingFilter) {
        this.samlLogoutProcessingFilter = samlLogoutProcessingFilter;
    }

    @Autowired(required = false)
    public void setSamlEntryPoint(SAMLEntryPoint samlEntryPoint) {
        this.samlEntryPoint = samlEntryPoint;
    }

    public boolean isWantAuthnRequestSigned() {
        return wantAuthnRequestSigned;
    }

    public void setWantAuthnRequestSigned(boolean wantAuthnRequestSigned) {
        this.wantAuthnRequestSigned = wantAuthnRequestSigned;
    }

    public Collection<String> getNameID() {
        return nameID == null ? defaultNameID : nameID;
    }

    public void setNameID(Collection<String> nameID) {
        this.nameID = nameID;
    }

    public String getEntityBaseURL() {
        return entityBaseURL;
    }

    public void setEntityBaseURL(String entityBaseURL) {
        this.entityBaseURL = entityBaseURL;
    }

    @Autowired
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public String getEntityId() {
        return entityId;
    }

    public Collection<String> getBindingsSSO() {
        return bindingsSSO;
    }

    /**
     * List of bindings to be included in the generated metadata for Web Single Sign-On. Ordering of bindings affects
     * inclusion in the generated metadata.
     *
     * Supported values are: "post" (or
     * "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").
     *
     * The following bindings are included by default: "post"
     *
     * @param bindingsSSO
     *            bindings for web single sign-on
     */
    public void setBindingsSSO(Collection<String> bindingsSSO) {
        this.bindingsSSO = Objects.requireNonNullElse(bindingsSSO, Collections.emptyList());
    }

    public Collection<String> getBindingsSLO() {
        return bindingsSLO;
    }

    /**
     * List of bindings to be included in the generated metadata for Single Logout. Ordering of bindings affects
     * inclusion in the generated metadata.
     *
     * Supported values are: "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") and "redirect" (or
     * "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect").
     *
     * The following bindings are included by default: "post", "redirect"
     *
     * @param bindingsSLO
     *            bindings for single logout
     */
    public void setBindingsSLO(Collection<String> bindingsSLO) {
        this.bindingsSLO = Objects.requireNonNullElse(bindingsSLO, Collections.emptyList());
    }

    public Collection<String> getBindingsHoKSSO() {
        return bindingsHoKSSO;
    }

    /**
     * List of bindings to be included in the generated metadata for Web Single Sign-On Holder of Key. Ordering of
     * bindings affects inclusion in the generated metadata.
     *
     * "post" (or
     * "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").
     *
     * By default there are no included bindings for the profile.
     *
     * @param bindingsHoKSSO
     *            bindings for web single sign-on holder-of-key
     */
    public void setBindingsHoKSSO(Collection<String> bindingsHoKSSO) {
        this.bindingsHoKSSO = Objects.requireNonNullElse(bindingsHoKSSO, Collections.emptyList());
    }

    public boolean isIncludeDiscoveryExtension() {
        return includeDiscoveryExtension;
    }

    /**
     * When true discovery profile extension metadata pointing to the default SAMLEntryPoint will be generated and
     * stored in the generated metadata document.
     *
     * @param includeDiscoveryExtension
     *            flag indicating whether IDP discovery should be enabled
     */
    public void setIncludeDiscoveryExtension(boolean includeDiscoveryExtension) {
        this.includeDiscoveryExtension = includeDiscoveryExtension;
    }

    public int getAssertionConsumerIndex() {
        return assertionConsumerIndex;
    }

    /**
     * Generated assertion consumer service with the index equaling set value will be marked as default. Use negative
     * value to skip the default attribute altogether.
     *
     * @param assertionConsumerIndex
     *            assertion consumer index of service to mark as default
     */
    public void setAssertionConsumerIndex(int assertionConsumerIndex) {
        this.assertionConsumerIndex = assertionConsumerIndex;
    }

    /**
     * True when IDP discovery is enabled either on local property includeDiscovery or property idpDiscoveryEnabled in
     * the extended metadata.
     *
     * @return true when discovery is enabled
     */
    protected boolean isIncludeDiscovery() {
        return extendedMetadata != null && extendedMetadata.isIdpDiscoveryEnabled();
    }

    /**
     * Provides set discovery request url or generates a default when none was provided. Primarily value set on
     * extenedMetadata property idpDiscoveryURL is used, when empty local property customDiscoveryURL is used, when
     * empty URL is automatically generated.
     *
     * @param entityBaseURL
     *            base URL for generation of endpoints
     * @param entityAlias
     *            alias of entity, or null when there's no alias required
     * @return URL to use for IDP discovery request
     */
    protected String getDiscoveryURL(String entityBaseURL, String entityAlias) {
        if (extendedMetadata != null && extendedMetadata.getIdpDiscoveryURL() != null
                && extendedMetadata.getIdpDiscoveryURL().length() > 0) {
            return extendedMetadata.getIdpDiscoveryURL();
        } else {
            return getServerURL(entityBaseURL, entityAlias, getSAMLDiscoveryPath());
        }
    }

    /**
     * Provides set discovery response url or generates a default when none was provided. Primarily value set on
     * extenedMetadata property idpDiscoveryResponseURL is used, when empty local property customDiscoveryResponseURL
     * is used, when empty URL is automatically generated.
     *
     * @param entityBaseURL
     *            base URL for generation of endpoints
     * @param entityAlias
     *            alias of entity, or null when there's no alias required
     * @return URL to use for IDP discovery response
     */
    protected String getDiscoveryResponseURL(String entityBaseURL, String entityAlias) {
        if (extendedMetadata != null && extendedMetadata.getIdpDiscoveryResponseURL() != null
                && extendedMetadata.getIdpDiscoveryResponseURL().length() > 0) {
            return extendedMetadata.getIdpDiscoveryResponseURL();
        } else {
            Map<String, String> params = new HashMap<String, String>();
            params.put(SAMLEntryPoint.DISCOVERY_RESPONSE_PARAMETER, "true");
            return getServerURL(entityBaseURL, entityAlias, getSAMLEntryPointPath(), params);
        }
    }

    /**
     * Provides key used for signing from extended metadata. Uses default key when key is not specified.
     *
     * @return signing key
     */
    protected String getSigningKey() {
        if (extendedMetadata != null && extendedMetadata.getSigningKey() != null) {
            return extendedMetadata.getSigningKey();
        } else {
            return keyManager.getDefaultCredentialName();
        }
    }

    /**
     * Provides key used for encryption from extended metadata. Uses default when key is not specified.
     *
     * @return encryption key
     */
    protected String getEncryptionKey() {
        if (extendedMetadata != null && extendedMetadata.getEncryptionKey() != null) {
            return extendedMetadata.getEncryptionKey();
        } else {
            return keyManager.getDefaultCredentialName();
        }
    }

    /**
     * Provides key used for SSL/TLS from extended metadata. Uses null when key is not specified.
     *
     * @return tls key
     */
    protected String getTLSKey() {
        if (extendedMetadata != null && extendedMetadata.getTlsKey() != null) {
            return extendedMetadata.getTlsKey();
        } else {
            return null;
        }
    }

    /**
     * Provides entity alias from extended metadata, or null when metadata isn't specified or contains null.
     *
     * @return entity alias
     */
    protected String getEntityAlias() {
        if (extendedMetadata != null) {
            return extendedMetadata.getAlias();
        } else {
            return null;
        }
    }

    public boolean isAssertionsSigned() {
        if (extendedMetadata != null) {
            return extendedMetadata.isAssertionsSigned();
        } else {
            return true;
        }
    }

    public int getAssertionTimeToLiveSeconds() {
        if (extendedMetadata != null) {
            return extendedMetadata.getAssertionTimeToLiveSeconds();
        } else {
            return 600;
        }
    }

    /**
     * Extended metadata which contains details on configuration of the generated service provider metadata.
     *
     * @return extended metadata
     */
    public ExtendedMetadata getExtendedMetadata() {
        return extendedMetadata;
    }

    /**
     * Default value for generation of extended metadata. Value is cloned upon each request to generate new
     * ExtendedMetadata object.
     *
     * @param extendedMetadata
     *            default extended metadata or null
     */
    public void setExtendedMetadata(IdpExtendedMetadata extendedMetadata) {
        this.extendedMetadata = extendedMetadata;
    }
}
