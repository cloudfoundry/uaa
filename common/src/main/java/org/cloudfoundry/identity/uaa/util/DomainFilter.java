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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Collections.EMPTY_LIST;

public class DomainFilter {

    private static Log logger = LogFactory.getLog(DomainFilter.class);

    public List<IdentityProvider> filter(List<IdentityProvider> activeProviders, ClientDetails client, String email) {
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
                if (explicitlyMatched.size()>0) {
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

    protected List<String> getProvidersForClient(ClientDetails client) {
        if (client==null) {
            return null;
        } else {
            return (List<String>) client.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);
        }
    }

    protected List<String> getEmailDomain(IdentityProvider provider) {
        AbstractIdentityProviderDefinition definition = null;
        if (provider.getConfig()!=null) {
            switch (provider.getType()) {
                case Origin.UAA: {
                    definition = provider.getConfigValue(UaaIdentityProviderDefinition.class);
                    break;
                }
                case Origin.LDAP: {
                    try {
                        definition = provider.getConfigValue(LdapIdentityProviderDefinition.class);
                    } catch (JsonUtils.JsonUtilException x) {
                        logger.error("Unable to parse LDAP configuration:"+provider.getConfig());
                    }
                    break;
                }
                case Origin.SAML: {
                    definition = provider.getConfigValue(SamlIdentityProviderDefinition.class);
                    break;
                }
                default: {
                    break;
                }
            }
        }
        if (definition!=null) {
            return definition.getEmailDomain();
        }
        return null;
    }


    protected boolean doesEmailDomainMatchProvider(IdentityProvider provider, String domain, boolean explicit) {
        List<String> domainList = getEmailDomain(provider);
        if (explicit && Origin.UAA.equals(provider.getOriginKey())) {
            return domainList == null ? false : domainList.contains(domain);
        } else {
            return domainList == null ? true : domainList.contains(domain);
        }
    }

}
