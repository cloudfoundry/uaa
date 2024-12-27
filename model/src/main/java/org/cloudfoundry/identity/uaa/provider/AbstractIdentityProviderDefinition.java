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

package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AbstractIdentityProviderDefinition {
    public static final String EMAIL_DOMAIN_ATTR = "emailDomain";
    public static final String PROVIDER_DESCRIPTION = "providerDescription";

    private List<String> emailDomain;
    private Map<String, Object> additionalConfiguration;
    private String providerDescription;

    public List<String> getEmailDomain() {
        return emailDomain;
    }

    public AbstractIdentityProviderDefinition setEmailDomain(List<String> emailDomain) {
        this.emailDomain = emailDomain;
        return this;
    }

    public Map<String, Object> getAdditionalConfiguration() {
        return additionalConfiguration;
    }

    public AbstractIdentityProviderDefinition setAdditionalConfiguration(Map<String, Object> additionalConfiguration) {
        this.additionalConfiguration = additionalConfiguration;
        return this;
    }

    public String getProviderDescription() {
        return providerDescription;
    }

    public void setProviderDescription(String description) {
        this.providerDescription = description;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        AbstractIdentityProviderDefinition that = (AbstractIdentityProviderDefinition) o;

        return Objects.equals(emailDomain, that.emailDomain);

    }

    @Override
    public int hashCode() {
        return emailDomain != null ? emailDomain.hashCode() : 0;
    }
}
