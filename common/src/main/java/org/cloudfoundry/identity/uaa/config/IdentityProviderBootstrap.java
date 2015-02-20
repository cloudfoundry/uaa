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
package org.cloudfoundry.identity.uaa.config;


import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.EmptyResultDataAccessException;

public class IdentityProviderBootstrap implements InitializingBean {

    private IdentityProviderProvisioning provisioning;
    private List<IdentityProvider> providers = new LinkedList<>();


    public IdentityProviderBootstrap(IdentityProviderProvisioning provisioning) {
        if (provisioning==null) {
            throw new NullPointerException("Constructor argument can't be null.");
        }
        this.provisioning = provisioning;
    }

    public void setSamlProviders(IdentityProviderConfigurator configurator) {
        if (configurator==null) {
            throw new NullPointerException();
        }
        for (IdentityProviderDefinition def : configurator.getIdentityProviderDefinitions()) {
            IdentityProvider provider = new IdentityProvider();
            provider.setType(Origin.SAML);
            provider.setOriginKey(def.getIdpEntityAlias());
            provider.setName("UAA SAML Identity Provider["+provider.getOriginKey()+"]");
            try {
                provider.setConfig(new ObjectMapper().writeValueAsString(def));
            } catch (IOException x) {
                throw new RuntimeException("Non serializable LDAP config");
            }
            providers.add(provider);
        }
    }

    public void setLdapConfig(HashMap<String, Object> ldapConfig) {
        if (ldapConfig != null) {
            IdentityProvider provider = new IdentityProvider();
            provider.setOriginKey(Origin.LDAP);
            provider.setType(Origin.LDAP);
            provider.setName("UAA LDAP Provider");
            try {
                provider.setConfig(new ObjectMapper().writeValueAsString(ldapConfig));
            } catch (IOException x) {
                throw new RuntimeException("Non serializable LDAP config");
            }
            providers.add(provider);
        }
    }


    @Override
    public void afterPropertiesSet() throws Exception {
        String zoneId = IdentityZone.getUaa().getId();
        for (IdentityProvider provider: providers) {
            IdentityProvider existing = null;
            try {
                existing = provisioning.retrieveByOrigin(provider.getOriginKey(), zoneId);
            }catch (EmptyResultDataAccessException x){
            }
            provider.setIdentityZoneId(zoneId);
            if (existing==null) {
                provisioning.create(provider);
            } else {
                provider.setId(existing.getId());
                provider.setCreated(existing.getCreated());
                provider.setVersion(existing.getVersion());
                provider.setLastModified(new Date(System.currentTimeMillis()));
                provisioning.update(provider);

            }
        }
    }
}
