/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.ExtendedMetadataProvider;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.util.StringUtils;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


public class NonSnarlIdpMetadataManager extends IdpMetadataManager implements ExtendedMetadataProvider, InitializingBean, DisposableBean, BeanNameAware {
    private static final Logger logger = LoggerFactory.getLogger(NonSnarlIdpMetadataManager.class);

    private SamlServiceProviderConfigurator configurator;


    private IdpMetadataGenerator generator;
    private Map<String, String> zoneHostedIdpNames;
    private ExtendedMetadata defaultExtendedMetadata;
    private String beanName = NonSnarlIdpMetadataManager.class.getName() + "-" + System.identityHashCode(this);

    public NonSnarlIdpMetadataManager(SamlServiceProviderConfigurator configurator) throws MetadataProviderException {
        super(Collections.<MetadataProvider>emptyList());
        this.configurator = configurator;

        super.setKeyManager(IdentityZoneHolder.getSamlSPKeyManager());
        //disable internal timer
        super.setRefreshCheckInterval(0);
        logger.info("-----> Internal Timer is disabled");
        this.defaultExtendedMetadata = new ExtendedMetadata();
        if (zoneHostedIdpNames == null) {
            zoneHostedIdpNames = new ConcurrentHashMap<>();
        }
    }

    @Override
    public void setBeanName(String name) {
        this.beanName = name;
    }

    @Override
    public void setProviders(List<MetadataProvider> newProviders) {
    }

    @Override
    public void refreshMetadata() {
    }

    @Override
    public void addMetadataProvider(MetadataProvider newProvider) {
    }

    @Override
    public void removeMetadataProvider(MetadataProvider provider) {
    }

    @Override
    public List<MetadataProvider> getProviders() {
        return new ArrayList<>(getAvailableProviders());
    }

    @Override
    public List<ExtendedMetadataDelegate> getAvailableProviders() {
        IdentityZone zone = IdentityZoneHolder.get();
        List<ExtendedMetadataDelegate> result = new ArrayList<>();
        try {
            result.add(getLocalIdp());
        } catch (MetadataProviderException e) {
            throw new IllegalStateException(e);
        }
        for (SamlServiceProviderHolder holder : configurator.getSamlServiceProviders()) {
            log.info("Adding SAML SP zone[" + zone.getId() + "] alias[" + holder.getSamlServiceProvider().getEntityId() + "]");
            try {
                ExtendedMetadataDelegate delegate = holder.getExtendedMetadataDelegate();
                initializeProvider(delegate);
                initializeProviderData(delegate);
                initializeProviderFilters(delegate);
                result.add(delegate);
            } catch (MetadataProviderException e) {
                log.error("Invalid SAML IDP zone[" + zone.getId() + "] alias[" + holder.getSamlServiceProvider().getEntityId() + "]", e);
            }
        }
        return result;

    }

    public ExtendedMetadataDelegate getLocalIdp() throws MetadataProviderException {
        EntityDescriptor descriptor = generator.generateMetadata();
        ExtendedMetadata extendedMetadata = generator.generateExtendedMetadata();
        log.info("Initialized local identity provider for entityID: " + descriptor.getEntityID());
        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor);
        memoryProvider.initialize();
        return new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
    }

    @Override
    protected void initializeProvider(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        log.debug("Initializing extendedMetadataDelegate {}", provider);
        provider.initialize();
    }

    @Override
    protected void initializeProviderData(ExtendedMetadataDelegate provider) {

    }

/*    @Override
    protected void initializeProviderFilters(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        getManager().initializeProviderFilters(provider);


    }*/

    @Override
    public Set<String> getIDPEntityNames() {
        Set<String> result = new HashSet<>();
        ExtendedMetadataDelegate delegate = null;
        try {
            delegate = getLocalIdp();
            String idp = getProviderIdpAlias(delegate);
            if (StringUtils.hasText(idp)) {
                result.add(idp);
            }
        } catch (MetadataProviderException e) {
            log.error("Unable to get IDP alias for:" + delegate, e);
        }
        return result;
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

    @Override
    public Set<String> getSPEntityNames() {
        Set<String> result = new HashSet<>();
        for (ExtendedMetadataDelegate delegate : getAvailableProviders()) {
            try {
                String sp = getSpName(delegate);
                if (StringUtils.hasText(sp)) {
                    result.add(sp);
                }
            } catch (MetadataProviderException e) {
                log.error("Unable to get IDP alias for:" + delegate, e);
            }
        }
        return result;
    }

    protected String getSpName(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        List<String> stringSet = parseProvider(provider);
        for (String key : stringSet) {
            RoleDescriptor spRoleDescriptor = provider.getRole(key, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
            if (spRoleDescriptor != null) {
                ExtendedMetadata extendedMetadata = getExtendedMetadata(key, provider);
                if (extendedMetadata != null) {
                    return key;
                }
            }
        }
        return null;
    }

    protected String getHostedSpName(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        String key = getSpName(provider);
        ExtendedMetadata extendedMetadata = getExtendedMetadata(key, provider);
        if (extendedMetadata.isLocal()) {
            return key;
        } else {
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
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

    /**
     * {@inheritDoc}
     */
    @Override
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
    public boolean isIDPValid(String idpID) {
        return getIDPEntityNames().contains(idpID);
    }

    @Override
    public boolean isSPValid(String spID) {
        return getSPEntityNames().contains(spID);
    }

    @Override
    public String getHostedIdpName() {
        return zoneHostedIdpNames.get(IdentityZoneHolder.get().getId());
    }

    @Override
    public void setHostedIdpName(String hostedIdpName) {
        String zoneId = IdentityZoneHolder.get().getId();
        zoneHostedIdpNames.put(zoneId, hostedIdpName);

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
                log.error("Unable to find hosted SP name:" + delegate, e);
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

    @Override
    public EntityDescriptor getEntityDescriptor(byte[] hash) throws MetadataProviderException {

        for (String sp : getSPEntityNames()) {
            if (SAMLUtil.compare(hash, sp)) {
                return getEntityDescriptor(sp);
            }
        }

        for (String idp : getIDPEntityNames()) {
            if (SAMLUtil.compare(hash, idp)) {
                return getEntityDescriptor(idp);
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

        for (String sp : getSPEntityNames()) {
            ExtendedMetadata extendedMetadata = getExtendedMetadata(sp);
            if (entityAlias.equals(extendedMetadata.getAlias())) {
                if (entityId != null && !entityId.equals(sp)) {
                    throw new MetadataProviderException("Alias " + entityAlias + " is used both for entity " + entityId + " and " + sp);
                } else {
                    entityId = sp;
                }
            }
        }

        for (String idp : getIDPEntityNames()) {
            ExtendedMetadata extendedMetadata = getExtendedMetadata(idp);
            if (entityAlias.equals(extendedMetadata.getAlias())) {
                if (entityId != null && !entityId.equals(idp)) {
                    throw new MetadataProviderException("Alias " + entityAlias + " is used both for entity " + entityId + " and " + idp);
                } else {
                    entityId = idp;
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
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
        super.setKeyManager(keyManager);
    }

    @Autowired(required = false)
    public void setTLSConfigurer(TLSProtocolConfigurer configurer) {
        // Only explicit dependency
    }

    @Override
    public void destroy() {

    }

    @Override
    public ExtendedMetadata getExtendedMetadata(String entityID) throws MetadataProviderException {
        for (MetadataProvider provider : getAvailableProviders()) {
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

    public IdpMetadataGenerator getGenerator() {
        return generator;
    }

    public void setGenerator(IdpMetadataGenerator generator) {
        this.generator = generator;
    }
}
