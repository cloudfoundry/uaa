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

import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;

public interface ComparableProvider extends Comparable<ComparableProvider> {

    String getAlias();
    String getZoneId();

    XMLObject doGetMetadata() throws MetadataProviderException;
    byte[] fetchMetadata() throws MetadataProviderException;

    default String getEntityID() throws MetadataProviderException {
        fetchMetadata();
        XMLObject metadata = doGetMetadata();
        if (metadata instanceof EntityDescriptor) {
            EntityDescriptor entityDescriptor = (EntityDescriptor) metadata;
            return entityDescriptor.getEntityID();
        } else if (metadata instanceof EntitiesDescriptor) {
            EntitiesDescriptor desc = (EntitiesDescriptor)metadata;
            if (desc.getEntityDescriptors().size()!=1) {
                throw new MetadataProviderException("Invalid metadata. Number of descriptors must be 1, but is "+desc.getEntityDescriptors().size());
            } else {
                return desc.getEntityDescriptors().get(0).getEntityID();
            }
        } else {
            throw new MetadataProviderException("Unknown descriptor class:"+metadata.getClass().getName());
        }
    }

    default int compareTo(ComparableProvider that) {
        if (this == that) return 0;
        int result = this.getAlias().compareTo(that.getAlias());
        if (0!=result) return result;
        result = this.getZoneId().compareTo(that.getZoneId());
        if (0!=result) return result;
        return 0;
    }

    default int getHashCode() {
        int result = getZoneId().hashCode();
        result = 31 * result + getAlias().hashCode();
        return result;
    }


}
