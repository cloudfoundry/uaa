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
package org.cloudfoundry.identity.uaa.login;

import java.util.ArrayList;
import java.util.Collection;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

/**
 * UserDetailsService that extracts the user's groups
 * 
 * @author jdsa
 * 
 */
public class LoginServerSamlUserDetailsService implements SAMLUserDetailsService {

    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        String username = credential.getNameID().getValue();
        String password = null;
        boolean enabled = true;
        boolean accountNonExpired = false;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;
        Collection<SamlUserAuthority> authorities = null;

        for (Attribute attribute : credential.getAttributes()) {
            if (("Groups".equals(attribute.getName())) || ("Groups".equals(attribute.getFriendlyName()))) {
                if (attribute.getAttributeValues() != null && attribute.getAttributeValues().size() > 0) {
                    authorities = new ArrayList<SamlUserAuthority>();
                    for (XMLObject group : attribute.getAttributeValues()) {
                        authorities.add(new SamlUserAuthority(((XSString) group).getValue()));
                    }
                }
                break;
            }
        }

        SamlUserDetails userDetails = new SamlUserDetails(username, password, enabled, accountNonExpired,
                        credentialsNonExpired, accountNonLocked, authorities == null ? UaaAuthority.USER_AUTHORITIES
                                        : authorities);

        return userDetails;
    }

}
