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
import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.config.NestedMapPropertySource;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdapIdentityProviderDefinition extends AbstractIdentityProviderDefinition {

    private String ldapProfileFile;
    private String baseUrl;
    private boolean skipSSLVerification;
    private String userDNPattern;

    private String bindUserDn;
    private String bindPassword;
    private String userSearchBase;
    private String userSearchFilter;

    private String passwordAttributeName;
    private String passwordEncoder;
    private String mailAttributeName;
    private String mailSubstitute;

    private boolean mailSubstituteOverridesLdap = false;
    private String ldapGroupFile;
    private String groupSearchBase;
    private String groupSearchFilter;

    private boolean autoAddGroups = true;
    private boolean groupSearchSubTree = true;
    private int maxGroupSearchDepth = 10;
    private String groupRoleAttribute;

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

    public static LdapIdentityProviderDefinition fromConfig(Map<String,Object> ldapConfig) {

        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        if (ldapConfig==null || ldapConfig.isEmpty()) {
            return definition;
        }
        NestedMapPropertySource source = new NestedMapPropertySource("ldap", ldapConfig);
        if (source.getProperty("emailDomain")!=null) {
            definition.setEmailDomain((List<String>) source.getProperty("emailDomain"));
        }

        definition.setLdapProfileFile((String) source.getProperty("profile.file"));
        if (definition.getLdapProfileFile()==null) {
            return definition;
        }
        switch (definition.getLdapProfileFile()) {
            case "ldap/ldap-simple-bind.xml" : {
                definition.setUserDNPattern((String) source.getProperty("base.userDnPattern"));
                break;
            }
            case "ldap/ldap-search-and-bind.xml":
            case "ldap/ldap-search-and-compare.xml" : {
                definition.setBindUserDn((String) source.getProperty("base.userDn"));
                definition.setBindPassword((String) source.getProperty("base.password"));
                definition.setUserSearchBase((String) source.getProperty("base.searchBase"));
                definition.setUserSearchFilter((String) source.getProperty("base.searchFilter"));
                break;
            }
            default: return definition;
        }

        definition.setBaseUrl((String) source.getProperty("base.url"));
        Boolean skipSslVerification = (Boolean) source.getProperty("ssl.skipverification");
        if (skipSslVerification!=null) {
            definition.setSkipSSLVerification(skipSslVerification);
        }
        Boolean mailSubstituteOverridesLdap = (Boolean)source.getProperty("base.mailSubstituteOverridesLdap");
        if (mailSubstituteOverridesLdap!=null) {
            definition.setMailSubstituteOverridesLdap(mailSubstituteOverridesLdap);
        }
        definition.setMailAttributeName((String) source.getProperty("base.mailAttributeName"));
        definition.setMailSubstitute((String) source.getProperty("base.mailSubstitute"));
        definition.setPasswordAttributeName((String) source.getProperty("base.passwordAttributeName"));
        definition.setPasswordEncoder((String) source.getProperty("base.passwordEncoder"));

        definition.setLdapGroupFile((String) source.getProperty("groups.file"));
        if (StringUtils.hasText(definition.getLdapGroupFile())) {
            definition.setGroupSearchBase((String) source.getProperty("groups.searchBase"));
            definition.setGroupSearchFilter((String) source.getProperty("groups.groupSearchFilter"));
            if (source.getProperty("groups.maxSearchDepth") != null) {
                definition.setMaxGroupSearchDepth((Integer) source.getProperty("groups.maxSearchDepth"));
            }
            Boolean searchSubTree = (Boolean) source.getProperty("groups.searchSubtree");
            if (searchSubTree != null) {
                definition.setGroupSearchSubTree(searchSubTree);
            }
            Boolean autoAdd = (Boolean) source.getProperty("groups.autoAdd");
            if (autoAdd!=null) {
                definition.setAutoAddGroups(autoAdd);
            }
            definition.setGroupRoleAttribute((String) source.getProperty("groups.groupRoleAttribute"));
        }
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

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getBindPassword() {
        return bindPassword;
    }

    public String getBindUserDn() {
        return bindUserDn;
    }

    public String getGroupSearchBase() {
        return groupSearchBase;
    }

    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    public String getLdapGroupFile() {
        return ldapGroupFile;
    }

    public String getLdapProfileFile() {
        return ldapProfileFile;
    }

    public String getMailAttributeName() {
        return mailAttributeName;
    }

    public String getMailSubstitute() {
        return mailSubstitute;
    }

    public boolean isMailSubstituteOverridesLdap() {
        return mailSubstituteOverridesLdap;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public boolean isGroupSearchSubTree() {
        return groupSearchSubTree;
    }

    public int getMaxGroupSearchDepth() {
        return maxGroupSearchDepth;
    }

    public boolean isSkipSSLVerification() {
        return skipSSLVerification;
    }

    public void setAutoAddGroups(boolean autoAddGroups) {
        this.autoAddGroups = autoAddGroups;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void setBindPassword(String bindPassword) {
        this.bindPassword = bindPassword;
    }

    public void setBindUserDn(String bindUserDn) {
        this.bindUserDn = bindUserDn;
    }

    public void setGroupSearchBase(String groupSearchBase) {
        this.groupSearchBase = groupSearchBase;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        this.groupSearchFilter = groupSearchFilter;
    }

    public void setGroupSearchSubTree(boolean groupSearchSubTree) {
        this.groupSearchSubTree = groupSearchSubTree;
    }

    public void setLdapGroupFile(String ldapGroupFile) {
        this.ldapGroupFile = ldapGroupFile;
    }

    public void setLdapProfileFile(String ldapProfileFile) {
        this.ldapProfileFile = ldapProfileFile;
    }

    public void setMailAttributeName(String mailAttributeName) {
        this.mailAttributeName = mailAttributeName;
    }

    public void setMailSubstitute(String mailSubstitute) {
        this.mailSubstitute = mailSubstitute;
    }

    public void setMailSubstituteOverridesLdap(boolean mailSubstituteOverridesLdap) {
        this.mailSubstituteOverridesLdap = mailSubstituteOverridesLdap;
    }

    public void setMaxGroupSearchDepth(int maxGroupSearchDepth) {
        this.maxGroupSearchDepth = maxGroupSearchDepth;
    }

    public void setSkipSSLVerification(boolean skipSSLVerification) {
        this.skipSSLVerification = skipSSLVerification;
    }

    public void setUserSearchBase(String userSearchBase) {
        this.userSearchBase = userSearchBase;
    }

    public void setUserSearchFilter(String userSearchFilter) {
        this.userSearchFilter = userSearchFilter;
    }

    public String getUserDNPattern() {
        return userDNPattern;
    }

    public void setUserDNPattern(String userDNPattern) {
        this.userDNPattern = userDNPattern;
    }

    public String getPasswordAttributeName() {
        return passwordAttributeName;
    }

    public void setPasswordAttributeName(String passwordAttributeName) {
        this.passwordAttributeName = passwordAttributeName;
    }

    public String getPasswordEncoder() {
        return passwordEncoder;
    }

    public void setPasswordEncoder(String passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public String getGroupRoleAttribute() {
        return groupRoleAttribute;
    }

    public void setGroupRoleAttribute(String groupRoleAttribute) {
        this.groupRoleAttribute = groupRoleAttribute;
    }

    @JsonIgnore
    public boolean isConfigured() {
        return StringUtils.hasText(getBaseUrl());
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
