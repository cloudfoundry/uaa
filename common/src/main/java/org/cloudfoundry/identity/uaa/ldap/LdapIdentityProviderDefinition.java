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
package org.cloudfoundry.identity.uaa.ldap;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.HashMap;
import java.util.Map;

public class LdapIdentityProviderDefinition {

    private String baseUrl;
    private String bindUserDn;
    private String bindPassword;
    private String userSearchBase;
    private String userSearchFilter;
    private String groupSearchBase;
    private String groupSearchFilter;
    private String mailAttributeName;
    private String mailSubstitute;
    private String ldapProfileFile;
    private String ldapGroupFile;
    private boolean mailSubstituteOverridesLdap;
    private boolean autoAddGroups;
    private boolean groupSearchSubTree;
    private int maxGroupSearchDepth;
    private boolean skipSSLVerification;

    public static LdapIdentityProviderDefinition searchAndBindMapGroupToScopes(
        String baseUrl,
        String bindUserDn,
        String bindPassword,
        String userSearchBase,
        String userSearchFilter,
        String groupSearchBase,
        String groupSearchFilter,
        String mailAttributeName,
        String mailSubstitute,
        boolean mailSubstituteOverridesLdap,
        boolean autoAddGroups,
        boolean groupSearchSubTree,
        int groupMaxSearchDepth,
        boolean skipSSLVerification) {

        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        definition.baseUrl = baseUrl;
        definition.bindUserDn = bindUserDn;
        definition.bindPassword = bindPassword;
        definition.userSearchBase = userSearchBase;
        definition.userSearchFilter = userSearchFilter;
        definition.groupSearchBase = groupSearchBase;
        definition.groupSearchFilter = groupSearchFilter;
        definition.mailAttributeName = mailAttributeName;
        definition.mailSubstitute = mailSubstitute;
        definition.ldapProfileFile="ldap/ldap-search-and-bind.xml";
        definition.ldapGroupFile="ldap/ldap-groups-map-to-scopes.xml";
        definition.mailSubstituteOverridesLdap = mailSubstituteOverridesLdap;
        definition.autoAddGroups = autoAddGroups;
        definition.groupSearchSubTree = groupSearchSubTree;
        definition.maxGroupSearchDepth = groupMaxSearchDepth;
        definition.skipSSLVerification = skipSSLVerification;
        return definition;
    }

    @JsonIgnore
    public ConfigurableEnvironment getLdapConfigurationEnvironment() {
        Map<String,Object> properties = new HashMap<>();

        properties.put("ldap.ssl.skipverification", isSkipSSLVerification());

        if ("ldap/ldap-search-and-bind.xml".equals(ldapProfileFile)) {
            properties.put("ldap.profile.file", getLdapProfileFile());
            properties.put("ldap.base.url", getBaseUrl());
            properties.put("ldap.base.userDn", getBindUserDn());
            properties.put("ldap.base.password", getBindPassword());
            properties.put("ldap.base.searchBase", getUserSearchBase());
            properties.put("ldap.base.searchFilter", getUserSearchFilter());
            properties.put("ldap.base.mailAttributeName", getMailAttributeName());
            properties.put("ldap.base.mailSubstitute", getMailSubstitute());
            properties.put("ldap.base.mailSubstituteOverridesLdap", isMailSubstituteOverridesLdap());
        }
        if ("ldap/ldap-groups-map-to-scopes.xml".equals(ldapGroupFile)) {
            properties.put("ldap.groups.file", getLdapGroupFile());
            properties.put("ldap.groups.autoAdd", isAutoAddGroups());
            properties.put("ldap.groups.searchBase", getGroupSearchBase());
            properties.put("ldap.groups.searchFilter", getGroupSearchFilter());
            properties.put("ldap.groups.searchSubtree", isGroupSearchSubTree());
            properties.put("ldap.groups.maxSearchDepth", getMaxGroupSearchDepth());
        }

        MapPropertySource source = new MapPropertySource("ldap", properties);
        return new LdapConfigEnvironment(source);
    }

    public boolean isAutoAddGroups() {
        return autoAddGroups;
    }

    public void setAutoAddGroups(boolean autoAddGroups) {
        this.autoAddGroups = autoAddGroups;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getBindPassword() {
        return bindPassword;
    }

    public void setBindPassword(String bindPassword) {
        this.bindPassword = bindPassword;
    }

    public String getBindUserDn() {
        return bindUserDn;
    }

    public void setBindUserDn(String bindUserDn) {
        this.bindUserDn = bindUserDn;
    }

    public String getGroupSearchBase() {
        return groupSearchBase;
    }

    public void setGroupSearchBase(String groupSearchBase) {
        this.groupSearchBase = groupSearchBase;
    }

    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        this.groupSearchFilter = groupSearchFilter;
    }

    public String getLdapGroupFile() {
        return ldapGroupFile;
    }

    public void setLdapGroupFile(String ldapGroupFile) {
        this.ldapGroupFile = ldapGroupFile;
    }

    public String getLdapProfileFile() {
        return ldapProfileFile;
    }

    public void setLdapProfileFile(String ldapProfileFile) {
        this.ldapProfileFile = ldapProfileFile;
    }

    public String getMailAttributeName() {
        return mailAttributeName;
    }

    public void setMailAttributeName(String mailAttributeName) {
        this.mailAttributeName = mailAttributeName;
    }

    public String getMailSubstitute() {
        return mailSubstitute;
    }

    public void setMailSubstitute(String mailSubstitute) {
        this.mailSubstitute = mailSubstitute;
    }

    public boolean isMailSubstituteOverridesLdap() {
        return mailSubstituteOverridesLdap;
    }

    public void setMailSubstituteOverridesLdap(boolean mailSubstituteOverridesLdap) {
        this.mailSubstituteOverridesLdap = mailSubstituteOverridesLdap;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public void setUserSearchBase(String userSearchBase) {
        this.userSearchBase = userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public void setUserSearchFilter(String userSearchFilter) {
        this.userSearchFilter = userSearchFilter;
    }

    public boolean isGroupSearchSubTree() {
        return groupSearchSubTree;
    }

    public void setGroupSearchSubTree(boolean groupSearchSubTree) {
        this.groupSearchSubTree = groupSearchSubTree;
    }

    public int getMaxGroupSearchDepth() {
        return maxGroupSearchDepth;
    }

    public void setMaxGroupSearchDepth(int maxGroupSearchDepth) {
        this.maxGroupSearchDepth = maxGroupSearchDepth;
    }

    public boolean isSkipSSLVerification() {
        return skipSSLVerification;
    }

    public void setSkipSSLVerification(boolean skipSSLVerification) {
        this.skipSSLVerification = skipSSLVerification;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof LdapIdentityProviderDefinition)) return false;

        LdapIdentityProviderDefinition that = (LdapIdentityProviderDefinition) o;

        if (autoAddGroups != that.autoAddGroups) return false;
        if (mailSubstituteOverridesLdap != that.mailSubstituteOverridesLdap) return false;
        if (!baseUrl.equals(that.baseUrl)) return false;
        if (bindPassword != null ? !bindPassword.equals(that.bindPassword) : that.bindPassword != null) return false;
        if (bindUserDn != null ? !bindUserDn.equals(that.bindUserDn) : that.bindUserDn != null) return false;
        if (groupSearchBase != null ? !groupSearchBase.equals(that.groupSearchBase) : that.groupSearchBase != null)
            return false;
        if (groupSearchFilter != null ? !groupSearchFilter.equals(that.groupSearchFilter) : that.groupSearchFilter != null)
            return false;
        if (!ldapGroupFile.equals(that.ldapGroupFile)) return false;
        if (!ldapProfileFile.equals(that.ldapProfileFile)) return false;
        if (!mailAttributeName.equals(that.mailAttributeName)) return false;
        if (mailSubstitute != null ? !mailSubstitute.equals(that.mailSubstitute) : that.mailSubstitute != null)
            return false;
        if (userSearchBase != null ? !userSearchBase.equals(that.userSearchBase) : that.userSearchBase != null)
            return false;
        if (userSearchFilter != null ? !userSearchFilter.equals(that.userSearchFilter) : that.userSearchFilter != null)
            return false;
        if (groupSearchSubTree!=that.groupSearchSubTree)
            return false;
        if (maxGroupSearchDepth!=that.maxGroupSearchDepth)
            return false;
        if (skipSSLVerification!=that.skipSSLVerification)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = baseUrl.hashCode();
        result = 31 * result + (bindUserDn != null ? bindUserDn.hashCode() : 0);
        result = 31 * result + (bindPassword != null ? bindPassword.hashCode() : 0);
        result = 31 * result + (userSearchBase != null ? userSearchBase.hashCode() : 0);
        result = 31 * result + (userSearchFilter != null ? userSearchFilter.hashCode() : 0);
        result = 31 * result + (groupSearchBase != null ? groupSearchBase.hashCode() : 0);
        result = 31 * result + (groupSearchFilter != null ? groupSearchFilter.hashCode() : 0);
        result = 31 * result + mailAttributeName.hashCode();
        result = 31 * result + (mailSubstitute != null ? mailSubstitute.hashCode() : 0);
        result = 31 * result + ldapProfileFile.hashCode();
        result = 31 * result + ldapGroupFile.hashCode();
        result = 31 * result + (mailSubstituteOverridesLdap ? 1 : 0);
        result = 31 * result + (autoAddGroups ? 1 : 0);
        result = 31 * result + (groupSearchSubTree ? 1 : 0);
        result = 31 * result + (skipSSLVerification ? 1 : 0);
        result = 31 * result + maxGroupSearchDepth;
        return result;
    }

    public static class LdapConfigEnvironment extends AbstractEnvironment {
        public LdapConfigEnvironment(MapPropertySource source) {
            getPropertySources().addFirst(source);
        }
    }
}
