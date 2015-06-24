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

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.util.SAMLUtil;

public class ZoneAwareMetadataGenerator extends MetadataGenerator {

    @Override
    public ExtendedMetadata generateExtendedMetadata() {
        ExtendedMetadata metadata = super.generateExtendedMetadata();
        metadata.setAlias(UaaUrlUtils.getSubdomain()+metadata.getAlias());
        return metadata;
    }

    @Override
    public String getEntityId() {
        String entityId = super.getEntityId();
        if (UaaUrlUtils.isUrl(entityId)) {
            return UaaUrlUtils.addSubdomainToUrl(entityId);
        } else {
            return UaaUrlUtils.getSubdomain()+entityId;
        }
    }

    @Override
    public String getEntityBaseURL() {
        return UaaUrlUtils.addSubdomainToUrl(super.getEntityBaseURL());
    }

    @Override
    protected String getEntityAlias() {
        return UaaUrlUtils.getSubdomain() + super.getEntityAlias();
    }

    @Override
    public EntityDescriptor generateMetadata() {
        EntityDescriptor result = super.generateMetadata();
        result.setID(SAMLUtil.getNCNameString(result.getEntityID()));
        return result;
    }
}
