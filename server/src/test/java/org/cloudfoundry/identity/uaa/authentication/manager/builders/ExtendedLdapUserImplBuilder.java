package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExtendedLdapUserImpl;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.HashMap;
import java.util.Map;

public class ExtendedLdapUserImplBuilder {
    private Map<String, String[]> ldapAttrs = new HashMap<>();
    private LdapUserDetails ldapUserDetails;
    private String mailAttributeName;

    public static ExtendedLdapUserImplBuilder anExtendedLdapUserImpl() {
        return new ExtendedLdapUserImplBuilder();
    }

    public ExtendedLdapUserImplBuilder withMailAttribute(String attributeName, String attributeValue) {
        ldapAttrs.put(attributeName, new String[]{attributeValue});
        this.mailAttributeName = attributeName;
        return this;
    }

    public ExtendedLdapUserImplBuilder withLdapUserDetails(LdapUserDetails ldapUserDetails) {
        this.ldapUserDetails = ldapUserDetails;
        return this;
    }

    public ExtendedLdapUserImpl build() {
        ExtendedLdapUserImpl extendedLdapUserDetails = new ExtendedLdapUserImpl(ldapUserDetails, ldapAttrs);
        extendedLdapUserDetails.setMailAttributeName(mailAttributeName);
        return extendedLdapUserDetails;
    }
}
