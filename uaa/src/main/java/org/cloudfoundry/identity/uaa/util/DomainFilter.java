/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.Collections.EMPTY_LIST;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

public class DomainFilter {

    private static Logger logger = LoggerFactory.getLogger(DomainFilter.class);

    public static List<IdentityProvider> filter(List<IdentityProvider> activeProviders, ClientDetails client, String email) {
        return filter(activeProviders, client, email, true);
    }

    public static List<IdentityProvider> filter(List<IdentityProvider> activeProviders, ClientDetails client, String email, boolean useUaaFallback) {
        if (!StringUtils.hasText(email)) {
            return EMPTY_LIST;
        }

        if (activeProviders!=null && activeProviders.size()>0) {
            //filter client providers
            List<String> clientFilter = getProvidersForClient(client);
            if (clientFilter!=null) {
                activeProviders =
                    activeProviders.stream().filter(
                        p -> clientFilter.contains(p.getOriginKey())
                    ).collect(Collectors.toList());
            }
            //filter for email domain
            if (email!=null && email.contains("@")) {
                final String domain = email.substring(email.indexOf('@') + 1);
                List<IdentityProvider> explicitlyMatched =
                    activeProviders.stream().filter(
                        p -> doesEmailDomainMatchProvider(p, domain, true)
                    ).collect(Collectors.toList());
                if (explicitlyMatched.size()>0 || !useUaaFallback) {
                    return explicitlyMatched;
                }

                activeProviders =
                    activeProviders.stream().filter(
                        p -> doesEmailDomainMatchProvider(p, domain, false)
                    ).collect(Collectors.toList());
            }
        }
        return activeProviders != null ? activeProviders : EMPTY_LIST;
    }

    public static List<IdentityProvider> getIdpsForEmailDomain(List<IdentityProvider> activeProviders, String email) {
        if (!StringUtils.hasText(email) || !email.contains("@")) {
            return EMPTY_LIST;
        }
        final String domain = email.substring(email.indexOf('@') + 1);
        return activeProviders.stream().filter(provider -> doesEmailDomainMatchProvider(provider, domain, true)).collect(Collectors.toList());
    }

    protected static List<String> getProvidersForClient(ClientDetails client) {
        if (client==null) {
            return null;
        } else {
            return (List<String>) client.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);
        }
    }

    protected static List<String> getEmailDomain(IdentityProvider provider) {
        if (provider.getConfig()!=null) {
            return provider.getConfig().getEmailDomain();
        }
        return null;
    }


    protected static boolean doesEmailDomainMatchProvider(IdentityProvider provider, String domain, boolean explicit) {
        List<String> domainList = getEmailDomain(provider);
        List<String> wildcardList;
        wildcardList = domainList;
        if (!explicit) {
            if (UAA.equals(provider.getOriginKey())) {
                wildcardList = domainList == null ? Arrays.asList("*.*", "*.*.*", "*.*.*.*") : domainList;
            }
        }

        if (wildcardList==null) {
            return false;
        } else {
            Set<Pattern> patterns = UaaStringUtils.constructWildcards(wildcardList);
            return UaaStringUtils.matches(patterns, domain);
        }
    }

}
