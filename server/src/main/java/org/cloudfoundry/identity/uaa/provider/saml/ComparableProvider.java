/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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
    byte[] fetchMetadata();

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
        int result = 0;

        if (this == that) return 0;

        if (this.getAlias() == null) {
            if(that.getAlias() != null) {
                return -1;
            }
        } else {
            if(that.getAlias() == null) {
                return 1;
            }
            result = this.getAlias().compareTo(that.getAlias());
            if(0!=result) return result;
        }

        if (this.getZoneId() == null) {
            if(that.getZoneId() != null) {
                return -1;
            }
        } else {
            if(that.getZoneId() == null) {
                return 1;
            }
            result = this.getZoneId().compareTo(that.getZoneId());
        }
        return result;
    }

    default int getHashCode() {
        int result = getZoneId() !=null ? getZoneId().hashCode():0;
        result = 31 * result + (getAlias() != null ? getAlias().hashCode():0);
        return result;
    }
}
