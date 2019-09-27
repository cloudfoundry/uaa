/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataFilterChain;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.SignatureValidationFilter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.NamespaceManager;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.security.x509.BasicPKIXValidationInformation;
import org.opensaml.xml.security.x509.BasicX509CredentialNameEvaluator;
import org.opensaml.xml.security.x509.CertPathPKIXValidationOptions;
import org.opensaml.xml.security.x509.PKIXValidationInformation;
import org.opensaml.xml.security.x509.PKIXValidationInformationResolver;
import org.opensaml.xml.security.x509.StaticPKIXValidationInformationResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.PKIXSignatureTrustEngine;
import org.opensaml.xml.util.IDIndex;
import org.opensaml.xml.util.LazySet;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.ExtendedMetadataProvider;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;
import org.springframework.security.saml.trust.AllowAllSignatureTrustEngine;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;


public class NonSnarlMetadataManager extends MetadataManager implements ExtendedMetadataProvider, InitializingBean, DisposableBean {

    // Class logger
    protected final Logger log = LoggerFactory.getLogger(NonSnarlMetadataManager.class);

    private ExtendedMetadata defaultExtendedMetadata;

    // Storage for cryptographic data used to verify metadata signatures
    protected KeyManager keyManager;

    private final SamlIdentityProviderConfigurator configurator;
    private ZoneAwareMetadataGenerator generator;

    public NonSnarlMetadataManager(SamlIdentityProviderConfigurator configurator) throws MetadataProviderException {
        super(Collections.EMPTY_LIST);
        this.configurator = configurator;
        this.defaultExtendedMetadata = new ExtendedMetadata();
        super.setRefreshCheckInterval(0);
    }

    @Override
    public void destroy() {

    }

    @Override
    public void setProviders(List<MetadataProvider> newProviders) {
    }

    @Override
    public void refreshMetadata() {
    }

    public ExtendedMetadataDelegate getLocalServiceProvider() throws MetadataProviderException {
        EntityDescriptor descriptor = generator.generateMetadata();
        ExtendedMetadata extendedMetadata = generator.generateExtendedMetadata();
        log.info("Initialized local service provider for entityID: " + descriptor.getEntityID());
        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor);
        memoryProvider.initialize();
        return new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
    }

    @Override
    public void addMetadataProvider(MetadataProvider newProvider) {
        //no op
    }

    @Override
    public void removeMetadataProvider(MetadataProvider provider) {
        //no op
    }

    public List<MetadataProvider> getProviders() {
        return new ArrayList<>(getAvailableProviders());
    }

    public List<ExtendedMetadataDelegate> getAvailableProviders() {
        IdentityZone zone = IdentityZoneHolder.get();
        List<ExtendedMetadataDelegate> result = new ArrayList<>();
        try {
            result.add(getLocalServiceProvider());
        } catch (MetadataProviderException e) {
            throw new IllegalStateException(e);
        }
        for (SamlIdentityProviderDefinition definition : configurator.getIdentityProviderDefinitions()) {
            log.info("Adding SAML IDP zone[" + zone.getId() + "] alias[" + definition.getIdpEntityAlias() + "]");
            try {
                ExtendedMetadataDelegate delegate = configurator.getExtendedMetadataDelegate(definition);
                initializeProvider(delegate);
                initializeProviderData(delegate);
                initializeProviderFilters(delegate);
                result.add(delegate);
            } catch (RestClientException | MetadataProviderException e) {
                log.error("Invalid SAML IDP zone[" + zone.getId() + "] alias[" + definition.getIdpEntityAlias() + "]", e);
            }
        }
        return result;
    }

    @Override
    protected void initializeProvider(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        // Initialize provider and perform signature verification
        log.debug("Initializing extendedMetadataDelegate {}", provider);
        provider.initialize();

    }

    protected String getProviderIdpAlias(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        List<String> stringSet = parseProvider(provider);
        for (String key : stringSet) {
            RoleDescriptor idpRoleDescriptor = provider.getRole(key, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
            if (idpRoleDescriptor != null) {
                return key;
            }
        }
        return null;
    }

    protected String getProviderSpAlias(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        List<String> stringSet = parseProvider(provider);
        for (String key : stringSet) {
            RoleDescriptor spRoleDescriptor = provider.getRole(key, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
            if (spRoleDescriptor != null) {
                return key;
            }
        }
        return null;
    }

    protected String getHostedSpName(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        List<String> stringSet = parseProvider(provider);
        for (String key : stringSet) {
            RoleDescriptor spRoleDescriptor = provider.getRole(key, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
            if (spRoleDescriptor != null) {
                ExtendedMetadata extendedMetadata = getExtendedMetadata(key, provider);
                if (extendedMetadata != null) {
                    if (extendedMetadata.isLocal()) {
                        return key;
                    }
                }
            }
        }
        return null;
    }

    protected String getProviderAlias(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        List<String> stringSet = parseProvider(provider);
        for (String key : stringSet) {
            // Verify extended metadata
            ExtendedMetadata extendedMetadata = getExtendedMetadata(key, provider);
            if (extendedMetadata != null) {
                if (extendedMetadata.isLocal()) {
                    // Parse alias
                    String alias = extendedMetadata.getAlias();
                    if (alias != null) {
                        // Verify alias is valid
                        SAMLUtil.verifyAlias(alias, key);
                        return alias;
                    } else {
                        log.debug("Local entity {} doesn't have an alias", key);

                    }
                } else {
                    log.debug("Remote entity {} available", key);
                }
            } else {
                log.debug("No extended metadata available for entity {}", key);
            }
        }
        return null;
    }
    /**
     * Method populates local storage of IDP and SP names and verifies any name conflicts which might arise.
     *
     * @param provider provider to initialize
     */
    protected void initializeProviderData(ExtendedMetadataDelegate provider) {
    }

    @Override
    protected void initializeProviderFilters(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        boolean requireSignature = provider.isMetadataRequireSignature();
        SignatureTrustEngine trustEngine = getTrustEngine(provider);
        SignatureValidationFilter filter = new SignatureValidationFilter(trustEngine);
        filter.setRequireSignature(requireSignature);

        log.debug("Created new trust manager for metadata provider {}", provider);

        // Combine any existing filters with the signature verification
        MetadataFilter currentFilter = provider.getMetadataFilter();
        if (currentFilter != null) {
            if (currentFilter instanceof MetadataFilterChain) {
                log.debug("Adding signature filter into existing chain");
                MetadataFilterChain chain = (MetadataFilterChain) currentFilter;
                chain.getFilters().add(filter);
            } else {
                log.debug("Combining signature filter with the existing in a new chain");
                MetadataFilterChain chain = new MetadataFilterChain();
                chain.getFilters().add(currentFilter);
                chain.getFilters().add(filter);
            }
        } else {
            log.debug("Adding signature filter");
            provider.setMetadataFilter(filter);
        }
    }

    @Override
    protected SignatureTrustEngine getTrustEngine(MetadataProvider provider) {

        Set<String> trustedKeys = null;
        boolean verifyTrust = true;
        boolean forceRevocationCheck = false;

        if (provider instanceof ExtendedMetadataDelegate) {
            ExtendedMetadataDelegate metadata = (ExtendedMetadataDelegate) provider;
            trustedKeys = metadata.getMetadataTrustedKeys();
            verifyTrust = metadata.isMetadataTrustCheck();
            forceRevocationCheck = metadata.isForceMetadataRevocationCheck();
        }

        if (verifyTrust) {

            log.debug("Setting trust verification for metadata provider {}", provider);

            CertPathPKIXValidationOptions pkixOptions = new CertPathPKIXValidationOptions();

            if (forceRevocationCheck) {
                log.debug("Revocation checking forced to true");
                pkixOptions.setForceRevocationEnabled(true);
            } else {
                log.debug("Revocation checking not forced");
                pkixOptions.setForceRevocationEnabled(false);
            }

            return new PKIXSignatureTrustEngine(
                getPKIXResolver(provider, trustedKeys, null),
                Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver(),
                new org.springframework.security.saml.trust.CertPathPKIXTrustEvaluator(pkixOptions),
                new BasicX509CredentialNameEvaluator());

        } else {

            log.debug("Trust verification skipped for metadata provider {}", provider);
            return new AllowAllSignatureTrustEngine(Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());

        }

    }

    @Override
    protected PKIXValidationInformationResolver getPKIXResolver(MetadataProvider provider, Set<String> trustedKeys, Set<String> trustedNames) {

        // Use all available keys
        if (trustedKeys == null) {
            trustedKeys = keyManager.getAvailableCredentials();
        }

        // Resolve allowed certificates to build the anchors
        List<X509Certificate> certificates = new LinkedList<X509Certificate>();
        for (String key : trustedKeys) {
            log.debug("Adding PKIX trust anchor {} for metadata verification of provider {}", key, provider);
            X509Certificate certificate = keyManager.getCertificate(key);
            if (certificate != null) {
                certificates.add(certificate);
            } else {
                log.warn("Cannot construct PKIX trust anchor for key with alias {} for provider {}, key isn't included in the keystore", key, provider);
            }
        }

        List<PKIXValidationInformation> info = new LinkedList<PKIXValidationInformation>();
        info.add(new BasicPKIXValidationInformation(certificates, null, 4));
        return new StaticPKIXValidationInformationResolver(info, trustedNames);

    }

    @Override
    protected List<String> parseProvider(MetadataProvider provider) throws MetadataProviderException {

        List<String> result = new LinkedList<String>();

        XMLObject object = provider.getMetadata();
        if (object instanceof EntityDescriptor) {
            addDescriptor(result, (EntityDescriptor) object);
        } else if (object instanceof EntitiesDescriptor) {
            addDescriptors(result, (EntitiesDescriptor) object);
        }

        return result;

    }

    private void addDescriptors(List<String> result, EntitiesDescriptor descriptors) throws MetadataProviderException {

        log.debug("Found metadata EntitiesDescriptor with ID", descriptors.getID());

        if (descriptors.getEntitiesDescriptors() != null) {
            for (EntitiesDescriptor descriptor : descriptors.getEntitiesDescriptors()) {
                addDescriptors(result, descriptor);
            }
        }
        if (descriptors.getEntityDescriptors() != null) {
            for (EntityDescriptor descriptor : descriptors.getEntityDescriptors()) {
                addDescriptor(result, descriptor);
            }
        }

    }

    /**
     * Parses entityID from the descriptor and adds it to the result set.  Signatures on all found entities
     * are verified using the given policy and trust engine.
     *
     * @param result     result set
     * @param descriptor descriptor to parse
     */
    private void addDescriptor(List<String> result, EntityDescriptor descriptor) {

        String entityID = descriptor.getEntityID();
        log.debug("Found metadata EntityDescriptor with ID", entityID);
        result.add(entityID);

    }

    @Override
    public Set<String> getIDPEntityNames() {
        Set<String> result = new HashSet<>();
        for (ExtendedMetadataDelegate delegate : getAvailableProviders()) {
            try {
                String idp = getProviderIdpAlias(delegate);
                if (StringUtils.hasText(idp)) {
                    result.add(idp);
                }
            } catch (MetadataProviderException e) {
                log.error("Unable to get IDP alias for:"+delegate, e);
            }
        }
        return result;
    }

    @Override
    public Set<String> getSPEntityNames() {
        Set<String> result = new HashSet<>();
        for (ExtendedMetadataDelegate delegate : getAvailableProviders()) {
            try {
                String sp = getHostedSpName(delegate);
                if (StringUtils.hasText(sp)) {
                    result.add(sp);
                }
            } catch (MetadataProviderException e) {
                log.error("Unable to get IDP alias for:"+delegate, e);
            }
        }
        return result;
    }

    @Override
    public boolean isIDPValid(String idpID) {
        return getIDPEntityNames().contains(idpID);
    }

    @Override
    public boolean isSPValid(String spID) {
        return getIDPEntityNames().contains(spID);
    }

    @Override
    public String getHostedSPName() {
        for (ExtendedMetadataDelegate delegate : getAvailableProviders()) {
            try {
                String spName = getHostedSpName(delegate);
                if (StringUtils.hasText(spName)) {
                    return spName;
                }
            } catch (MetadataProviderException e) {
                log.error("Unable to find hosted SP name:"+delegate, e);
            }
        }
        return null;
    }

    @Override
    public void setHostedSPName(String hostedSPName) {

    }

    @Override
    public String getDefaultIDP() throws MetadataProviderException {
        Iterator<String> iterator = getIDPEntityNames().iterator();
        if (iterator.hasNext()) {
            return iterator.next();
        } else {
            throw new MetadataProviderException("No IDP was configured, please update included metadata with at least one IDP");
        }
    }

    @Override
    public void setDefaultIDP(String defaultIDP) {
        //no op
    }

    @Override
    public ExtendedMetadata getExtendedMetadata(String entityID) throws MetadataProviderException {
        for (MetadataProvider provider : getProviders()) {
            ExtendedMetadata extendedMetadata = getExtendedMetadata(entityID, provider);
            if (extendedMetadata != null) {
                return extendedMetadata;
            }
        }
        return getDefaultExtendedMetadata().clone();
    }

    private ExtendedMetadata getExtendedMetadata(String entityID, MetadataProvider provider) throws MetadataProviderException {
        if (provider instanceof ExtendedMetadataProvider) {
            ExtendedMetadataProvider extendedProvider = (ExtendedMetadataProvider) provider;
            ExtendedMetadata extendedMetadata = extendedProvider.getExtendedMetadata(entityID);
            if (extendedMetadata != null) {
                return extendedMetadata.clone();
            }
        }
        return null;
    }

    @Override
    public EntityDescriptor getEntityDescriptor(byte[] hash) throws MetadataProviderException {
        for (String idp : getIDPEntityNames()) {
            if (SAMLUtil.compare(hash, idp)) {
                return getEntityDescriptor(idp);
            }
        }

        for (String sp : getSPEntityNames()) {
            if (SAMLUtil.compare(hash, sp)) {
                return getEntityDescriptor(sp);
            }
        }

        return null;
    }

    @Override
    public String getEntityIdForAlias(String entityAlias) throws MetadataProviderException {
        if (entityAlias == null) {
            return null;
        }

        String entityId = null;

        for (String idp : getIDPEntityNames()) {
            ExtendedMetadata extendedMetadata = getExtendedMetadata(idp);
            if (extendedMetadata.isLocal() && entityAlias.equals(extendedMetadata.getAlias())) {
                if (entityId != null && !entityId.equals(idp)) {
                    throw new MetadataProviderException("Alias " + entityAlias + " is used both for entity " + entityId + " and " + idp);
                } else {
                    entityId = idp;
                }
            }
        }

        for (String sp : getSPEntityNames()) {
            ExtendedMetadata extendedMetadata = getExtendedMetadata(sp);
            if (extendedMetadata.isLocal() && entityAlias.equals(extendedMetadata.getAlias())) {
                if (entityId != null && !entityId.equals(sp)) {
                    throw new MetadataProviderException("Alias " + entityAlias + " is used both for entity " + entityId + " and " + sp);
                } else {
                    entityId = sp;
                }
            }
        }

        return entityId;
    }

    @Override
    public ExtendedMetadata getDefaultExtendedMetadata() {
        return defaultExtendedMetadata;
    }

    @Override
    public void setDefaultExtendedMetadata(ExtendedMetadata defaultExtendedMetadata) {
        this.defaultExtendedMetadata = defaultExtendedMetadata;
    }

    @Override
    public boolean isRefreshRequired() {
        return false;
    }

    @Override
    public void setRefreshRequired(boolean refreshRequired) {
        //no op
    }


    @Override
    public void setRefreshCheckInterval(long refreshCheckInterval) {
        super.setRefreshCheckInterval(0);
    }

    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
        super.setKeyManager(keyManager);
    }

    @Autowired(required = false)
    public void setTLSConfigurer(TLSProtocolConfigurer configurer) {
        // Only explicit dependency
    }

    public EntitiesDescriptor getEntitiesDescriptor(String name) {
        EntitiesDescriptor descriptor = null;
        for (MetadataProvider provider : getProviders()) {
            log.debug("Checking child metadata provider for entities descriptor with name: {}", name);
            try {
                descriptor = provider.getEntitiesDescriptor(name);
                if (descriptor != null) {
                    break;
                }
            } catch (MetadataProviderException e) {
                log.warn("Error retrieving metadata from provider of type {}, proceeding to next provider",
                         provider.getClass().getName(), e);
                continue;
            }
        }
        return descriptor;
    }

    /** {@inheritDoc} */
    public EntityDescriptor getEntityDescriptor(String entityID) {
        EntityDescriptor descriptor = null;
        for (MetadataProvider provider : getProviders()) {
            log.debug("Checking child metadata provider for entity descriptor with entity ID: {}", entityID);
            try {
                descriptor = provider.getEntityDescriptor(entityID);
                if (descriptor != null) {
                    break;
                }
            } catch (MetadataProviderException e) {
                log.warn("Error retrieving metadata from provider of type {}, proceeding to next provider",
                         provider.getClass().getName(), e);
                continue;
            }
        }
        return descriptor;
    }

    /** {@inheritDoc} */
    public List<RoleDescriptor> getRole(String entityID, QName roleName) {
        List<RoleDescriptor> roleDescriptors = null;
        for (MetadataProvider provider : getProviders()) {
            log.debug("Checking child metadata provider for entity descriptor with entity ID: {}", entityID);
            try {
                roleDescriptors = provider.getRole(entityID, roleName);
                if (roleDescriptors != null && !roleDescriptors.isEmpty()) {
                    break;
                }
            } catch (MetadataProviderException e) {
                log.warn("Error retrieving metadata from provider of type {}, proceeding to next provider",
                         provider.getClass().getName(), e);
                continue;
            }
        }
        return roleDescriptors;
    }

    /** {@inheritDoc} */
    public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol) {
        RoleDescriptor roleDescriptor = null;
        for (MetadataProvider provider : getProviders()) {
            log.debug("Checking child metadata provider for entity descriptor with entity ID: {}", entityID);
            try {
                roleDescriptor = provider.getRole(entityID, roleName, supportedProtocol);
                if (roleDescriptor != null) {
                    break;
                }
            } catch (MetadataProviderException e) {
                log.warn("Error retrieving metadata from provider of type {}, proceeding to next provider",
                         provider.getClass().getName(), e);
                continue;
            }
        }
        return roleDescriptor;
    }

    @Override
    public XMLObject getMetadata() throws MetadataProviderException {
        return new ChainingEntitiesDescriptor();
    }

    public void setMetadataGenerator(ZoneAwareMetadataGenerator generator) throws BeansException {
        this.generator = generator;
    }

    public class ChainingEntitiesDescriptor implements EntitiesDescriptor {

        /** Metadata from the child metadata providers. */
        private ArrayList<XMLObject> childDescriptors;

        /** Constructor. */
        public ChainingEntitiesDescriptor() throws MetadataProviderException {
            childDescriptors = new ArrayList<XMLObject>();
            for (MetadataProvider provider : getProviders()) {
                childDescriptors.add(provider.getMetadata());
            }
        }

        /** {@inheritDoc} */
        public List<EntitiesDescriptor> getEntitiesDescriptors() {
            ArrayList<EntitiesDescriptor> descriptors = new ArrayList<>();
            for (XMLObject descriptor : childDescriptors) {
                if (descriptor instanceof EntitiesDescriptor) {
                    descriptors.add((EntitiesDescriptor) descriptor);
                }
            }

            return descriptors;
        }

        /** {@inheritDoc} */
        public List<EntityDescriptor> getEntityDescriptors() {
            ArrayList<EntityDescriptor> descriptors = new ArrayList<>();
            for (XMLObject descriptor : childDescriptors) {
                if (descriptor instanceof EntityDescriptor) {
                    descriptors.add((EntityDescriptor) descriptor);
                }
            }

            return descriptors;
        }

        /** {@inheritDoc} */
        public Extensions getExtensions() {
            return null;
        }

        /** {@inheritDoc} */
        public String getID() {
            return null;
        }

        /** {@inheritDoc} */
        public String getName() {
            return null;
        }

        /** {@inheritDoc} */
        public void setExtensions(Extensions extensions) {

        }

        /** {@inheritDoc} */
        public void setID(String newID) {

        }

        /** {@inheritDoc} */
        public void setName(String name) {

        }

        /** {@inheritDoc} */
        public String getSignatureReferenceID() {
            return null;
        }

        /** {@inheritDoc} */
        public Signature getSignature() {
            return null;
        }

        /** {@inheritDoc} */
        public boolean isSigned() {
            return false;
        }

        /** {@inheritDoc} */
        public void setSignature(Signature newSignature) {

        }

        /** {@inheritDoc} */
        public void addNamespace(Namespace namespace) {

        }

        /** {@inheritDoc} */
        public void detach() {

        }

        /** {@inheritDoc} */
        public Element getDOM() {
            return null;
        }

        /** {@inheritDoc} */
        public QName getElementQName() {
            return EntitiesDescriptor.DEFAULT_ELEMENT_NAME;
        }

        /** {@inheritDoc} */
        public IDIndex getIDIndex() {
            return null;
        }

        /** {@inheritDoc} */
        public NamespaceManager getNamespaceManager() {
            return null;
        }

        /** {@inheritDoc} */
        public Set<Namespace> getNamespaces() {
            return new LazySet<>();
        }

        /** {@inheritDoc} */
        public String getNoNamespaceSchemaLocation() {
            return null;
        }

        /** {@inheritDoc} */
        public List<XMLObject> getOrderedChildren() {
            ArrayList<XMLObject> descriptors = new ArrayList<>();
            try {
                for (MetadataProvider provider : getProviders()) {
                    descriptors.add(provider.getMetadata());
                }
            } catch (MetadataProviderException e) {
                log.error("Unable to generate list of child descriptors", e);
            }

            return descriptors;
        }

        /** {@inheritDoc} */
        public XMLObject getParent() {
            return null;
        }

        /** {@inheritDoc} */
        public String getSchemaLocation() {
            return null;
        }

        /** {@inheritDoc} */
        public QName getSchemaType() {
            return EntitiesDescriptor.TYPE_NAME;
        }

        /** {@inheritDoc} */
        public boolean hasChildren() {
            return !getOrderedChildren().isEmpty();
        }

        /** {@inheritDoc} */
        public boolean hasParent() {
            return false;
        }

        /** {@inheritDoc} */
        public void releaseChildrenDOM(boolean propagateRelease) {

        }

        /** {@inheritDoc} */
        public void releaseDOM() {

        }

        /** {@inheritDoc} */
        public void releaseParentDOM(boolean propagateRelease) {

        }

        /** {@inheritDoc} */
        public void removeNamespace(Namespace namespace) {

        }

        /** {@inheritDoc} */
        public XMLObject resolveID(String id) {
            return null;
        }

        /** {@inheritDoc} */
        public XMLObject resolveIDFromRoot(String id) {
            return null;
        }

        /** {@inheritDoc} */
        public void setDOM(Element dom) {

        }

        /** {@inheritDoc} */
        public void setNoNamespaceSchemaLocation(String location) {

        }

        /** {@inheritDoc} */
        public void setParent(XMLObject parent) {

        }

        /** {@inheritDoc} */
        public void setSchemaLocation(String location) {

        }

        /** {@inheritDoc} */
        public void deregisterValidator(Validator validator) {

        }

        /** {@inheritDoc} */
        public List<Validator> getValidators() {
            return new ArrayList<Validator>();
        }

        /** {@inheritDoc} */
        public void registerValidator(Validator validator) {
        }

        /** {@inheritDoc} */
        public void validate(boolean validateDescendants) {
        }

        /** {@inheritDoc} */
        public DateTime getValidUntil() {
            return null;
        }

        /** {@inheritDoc} */
        public boolean isValid() {
            return true;
        }

        /** {@inheritDoc} */
        public void setValidUntil(DateTime validUntil) {

        }

        /** {@inheritDoc} */
        public Long getCacheDuration() {
            return null;
        }

        /** {@inheritDoc} */
        public void setCacheDuration(Long duration) {

        }

        /** {@inheritDoc} */
        public Boolean isNil() {
            return Boolean.FALSE;
        }

        /** {@inheritDoc} */
        public XSBooleanValue isNilXSBoolean() {
            return new XSBooleanValue(Boolean.FALSE, false);
        }

        /** {@inheritDoc} */
        public void setNil(Boolean arg0) {
            // do nothing
        }

        /** {@inheritDoc} */
        public void setNil(XSBooleanValue arg0) {
            // do nothing
        }

    }
}