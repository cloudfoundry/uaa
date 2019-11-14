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

package org.cloudfoundry.identity.uaa.mfa;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class GoogleMfaProviderConfig extends AbstractMfaProviderConfig {

    private String providerDescription;

    public void validate() {}

    public String getProviderDescription() {
        return providerDescription;
    }

    public GoogleMfaProviderConfig setProviderDescription(String providerDescription) {
        this.providerDescription = providerDescription;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GoogleMfaProviderConfig that = (GoogleMfaProviderConfig) o;

        if (!Objects.equals(providerDescription, that.providerDescription))
            return false;
        return super.equals(that);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result += providerDescription != null ? providerDescription.hashCode() : 0;
        return result;
    }
}