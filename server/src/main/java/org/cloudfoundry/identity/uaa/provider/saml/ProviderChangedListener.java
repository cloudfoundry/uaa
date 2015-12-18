/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.event.IdentityProviderModifiedEvent;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationListener;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

public class ProviderChangedListener implements ApplicationListener<IdentityProviderModifiedEvent> {

    private static final Log logger = LogFactory.getLog(ProviderChangedListener.class);
    private ZoneAwareMetadataManager metadataManager = null;
    private final SamlIdentityProviderConfigurator configurator;
    private final IdentityZoneProvisioning zoneProvisioning;

    public ProviderChangedListener(SamlIdentityProviderConfigurator configurator,
                                   IdentityZoneProvisioning zoneProvisioning) {
        this.configurator = configurator;
        this.zoneProvisioning = zoneProvisioning;
    }

    @Override
    public void onApplicationEvent(IdentityProviderModifiedEvent event) {
        if (metadataManager==null) {
            return;
        }
        IdentityProvider eventProvider = (IdentityProvider)event.getSource();
        if (OriginKeys.SAML.equals(eventProvider.getType())) {
            IdentityProvider<SamlIdentityProviderDefinition> provider = (IdentityProvider<SamlIdentityProviderDefinition>)eventProvider;
            IdentityZone zone = zoneProvisioning.retrieve(provider.getIdentityZoneId());
            ZoneAwareMetadataManager.ExtensionMetadataManager manager = metadataManager.getManager(zone);
            SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(provider.getConfig(),SamlIdentityProviderDefinition.class);
            try {
                if (provider.isActive()) {
                    ExtendedMetadataDelegate[] delegates = configurator.addSamlIdentityProviderDefinition(definition);
                    if (delegates[1]!=null) {
                        manager.removeMetadataProvider(delegates[1]);
                    }
                    manager.addMetadataProvider(delegates[0]);
                } else {
                    ExtendedMetadataDelegate delegate = configurator.removeIdentityProviderDefinition(definition);
                    if (delegate!=null) {
                        manager.removeMetadataProvider(delegate);
                    }
                }
                for (MetadataProvider idp : manager.getProviders()) {
                    idp.getMetadata();
                }
                manager.refreshMetadata();
                metadataManager.getManager(zone).refreshMetadata();
            } catch (MetadataProviderException e) {
                logger.error("Unable to add new IDP provider:"+definition,e);
            }
        }
    }

    public void setMetadataManager(ZoneAwareMetadataManager metadataManager) {
        this.metadataManager = metadataManager;
    }
}
