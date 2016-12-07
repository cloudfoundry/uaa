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

import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.SimpleURLCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

/**
 * The filter expects calls on configured URL and presents user with SAML2 metadata representing this application
 * deployment. In case the application is configured to automatically generate metadata, the generation occurs upon
 * first invocation of this filter (first request made to the server).
 *
 * This class is based on org.springframework.security.saml.metadata.MetadataGeneratorFilter.
 */
public class IdpMetadataGeneratorFilter extends GenericFilterBean {

    /**
     * Class logger.
     */
    protected final static Logger log = LoggerFactory.getLogger(IdpMetadataGeneratorFilter.class);

    /**
     * Class storing all SAML metadata documents
     */
    protected IdpMetadataManager manager;

    /**
     * Class capable of generating new metadata.
     */
    protected IdpMetadataGenerator generator;

    /**
     * Metadata display filter.
     */
    protected MetadataDisplayFilter displayFilter;

    /**
     * Flag indicates that in case generated base url is used (when value is not provided in the MetadataGenerator) it
     * should be normalized. Normalization includes lower-casing of scheme and server name and removing standar ports
     * of 80 for http and 443 for https schemes.
     */
    protected boolean normalizeBaseUrl;

    /**
     * Default constructor.
     *
     * @param generator
     *            generator
     */
    public IdpMetadataGeneratorFilter(IdpMetadataGenerator generator) {
        this.generator = generator;
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        processMetadataInitialization((HttpServletRequest) request);
        chain.doFilter(request, response);
    }

    /**
     * Verifies whether generation is needed and if so the metadata document is created and stored in metadata
     * manager.
     *
     * @param request
     *            request
     * @throws javax.servlet.ServletException
     *             error
     */
    protected void processMetadataInitialization(HttpServletRequest request) throws ServletException {

        // In case the hosted IdP metadata weren't initialized, let's do it now
        if (manager.getHostedIdpName() == null) {

            synchronized (IdpMetadataManager.class) {

                if (manager.getHostedIdpName() == null) {

                    try {

                        log.info(
                                "No default metadata configured, generating with default values, please pre-configure metadata for production use");

                        // Defaults
                        String alias = generator.getEntityAlias();
                        String baseURL = getDefaultBaseURL(request);

                        // Use default baseURL if not set
                        if (generator.getEntityBaseURL() == null) {
                            log.warn(
                                    "Generated default entity base URL {} based on values in the first server request. Please set property entityBaseURL on MetadataGenerator bean to fixate the value.",
                                    baseURL);
                            generator.setEntityBaseURL(baseURL);
                        } else {
                            baseURL = generator.getEntityBaseURL();
                        }

                        // Use default entityID if not set
                        if (generator.getEntityId() == null) {
                            generator.setEntityId(getDefaultEntityID(baseURL, alias));
                        }

                        // Ensure supported nameID formats in uaa are listed in the metadata
                        Collection<String> supportedNameID = Arrays.asList(NameIDType.EMAIL, NameIDType.PERSISTENT,
                                NameIDType.UNSPECIFIED);
                        generator.setNameID(supportedNameID);

                        EntityDescriptor descriptor = generator.generateMetadata();
                        ExtendedMetadata extendedMetadata = generator.generateExtendedMetadata();

                        log.info("Created default metadata for system with entityID: " + descriptor.getEntityID());
                        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor);
                        memoryProvider.initialize();
                        MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider,
                                extendedMetadata);

                        manager.addMetadataProvider(metadataProvider);
                        manager.setHostedIdpName(descriptor.getEntityID());
                        manager.refreshMetadata();

                    } catch (MetadataProviderException e) {
                        log.error("Error generating system metadata", e);
                        throw new ServletException("Error generating system metadata", e);
                    }

                }

            }

        }

    }

    protected String getDefaultEntityID(String entityBaseUrl, String alias) {

        String displayFilterUrl = MetadataDisplayFilter.FILTER_URL;
        if (displayFilter != null) {
            displayFilterUrl = displayFilter.getFilterProcessesUrl();
        }

        StringBuilder sb = new StringBuilder();
        sb.append(entityBaseUrl);
        sb.append(displayFilterUrl);

        if (StringUtils.hasLength(alias)) {
            sb.append("/alias/");
            sb.append(alias);
        }

        return sb.toString();

    }

    protected String getDefaultBaseURL(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append(request.getScheme()).append("://").append(request.getServerName()).append(":")
                .append(request.getServerPort());
        sb.append(request.getContextPath());
        String url = sb.toString();
        if (isNormalizeBaseUrl()) {
            return SimpleURLCanonicalizer.canonicalize(url);
        } else {
            return url;
        }
    }

    @Autowired(required = false)
    public void setDisplayFilter(MetadataDisplayFilter displayFilter) {
        this.displayFilter = displayFilter;
    }

    @Autowired
    public void setManager(IdpMetadataManager manager) {
        this.manager = manager;
    }

    public boolean isNormalizeBaseUrl() {
        return normalizeBaseUrl;
    }

    /**
     * When true flag indicates that in case generated base url is used (when value is not provided in the
     * MetadataGenerator) it should be normalized. Normalization includes lower-casing of scheme and server name and
     * removing standar ports of 80 for http and 443 for https schemes.
     *
     * @param normalizeBaseUrl
     *            flag
     */
    public void setNormalizeBaseUrl(boolean normalizeBaseUrl) {
        this.normalizeBaseUrl = normalizeBaseUrl;
    }

    /**
     * Verifies that required entities were autowired or set.
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(generator, "Metadata generator");
        Assert.notNull(manager, "MetadataManager must be set");
    }

}
