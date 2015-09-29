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

package org.cloudfoundry.identity.uaa;

import java.util.LinkedHashMap;
import java.util.List;

public abstract class AbstractIdentityProviderDefinition {
    public static final String EMAIL_DOMAIN_ATTR = "emailDomain";
    public static final String ATTR_WHITELIST = "attributesWhitelist";

    private List<String> emailDomain;
    private LinkedHashMap<String, String> attributesWhitelist;

    public List<String> getEmailDomain() {
        return emailDomain;
    }

    public AbstractIdentityProviderDefinition setEmailDomain(List<String> emailDomain) {
        this.emailDomain = emailDomain;
        return this;
    }

    public LinkedHashMap<String, String> getAttributesWhitelist() {
        return attributesWhitelist;
    }

    public AbstractIdentityProviderDefinition setAttributesWhitelist(LinkedHashMap<String, String> attributesWhitelist) {
        this.attributesWhitelist = attributesWhitelist;
        return this;
    }
}
