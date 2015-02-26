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

package org.cloudfoundry.identity.uaa.login.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.event.IdentityProviderModifiedEvent;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationListener;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

public class ProviderChangedListener implements ApplicationListener<IdentityProviderModifiedEvent> {

    private static final Log logger = LogFactory.getLog(ProviderChangedListener.class);
    private final ZoneAwareMetadataManager metadataManager;
    private final IdentityProviderConfigurator configurator;
    private final IdentityZoneProvisioning zoneProvisioning;

    public ProviderChangedListener(IdentityProviderConfigurator configurator,
                                   ZoneAwareMetadataManager metadataManager,
                                   IdentityZoneProvisioning zoneProvisioning) {
        this.configurator = configurator;
        this.metadataManager = metadataManager;
        this.zoneProvisioning = zoneProvisioning;
    }

    @Override
    public void onApplicationEvent(IdentityProviderModifiedEvent event) {
        IdentityProvider provider = (IdentityProvider)event.getSource();
        if (Origin.SAML.equals(provider.getType())) {
            ExtendedMetadataDelegate delegate =
                configurator.addIdentityProviderDefinition(JsonUtils.readValue(provider.getConfig(), IdentityProviderDefinition.class));
            IdentityZone zone = zoneProvisioning.retrieve(provider.getIdentityZoneId());
            try {
                metadataManager.getManager(zone).addMetadataProvider(delegate);
            } catch (MetadataProviderException e) {
                logger.error("Unable to add new IDP provider:",e);
            }
        }
    }

}
