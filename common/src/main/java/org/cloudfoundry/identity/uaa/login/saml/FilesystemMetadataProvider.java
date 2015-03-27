/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.saml;


import org.opensaml.saml2.metadata.provider.MetadataProviderException;

import java.io.File;
import java.util.Timer;

public class FilesystemMetadataProvider extends org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider implements ComparableProvider {

    private final String zoneId;
    private final String alias;

    public FilesystemMetadataProvider(String zoneId, String alias, Timer backgroundTaskTimer, File metadata) throws MetadataProviderException {
        super(backgroundTaskTimer, metadata);
        this.zoneId = zoneId;
        this.alias = alias;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof ComparableProvider)) return false;

        ComparableProvider that = (ComparableProvider) o;

        if (!alias.equals(that.getAlias())) return false;
        if (!zoneId.equals(that.getZoneId())) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = zoneId.hashCode();
        result = 31 * result + alias.hashCode();
        return result;
    }

    @Override
    public String getAlias() {
        return alias;
    }

    @Override
    public String getZoneId() {
        return zoneId;
    }
}
