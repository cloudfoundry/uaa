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
import org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.config.NestedMapPropertySource;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdapIdentityProviderDefinition extends ExternalIdentityProviderDefinition {
    public static final String LDAP = "ldap";
    public static final String LDAP_PREFIX = LDAP + ".";
    public static final String LDAP_ATTRIBUTE_MAPPINGS = LDAP_PREFIX + ATTRIBUTE_MAPPINGS;
    public static final String LDAP_BASE_LOCAL_PASSWORD_COMPARE = LDAP_PREFIX + "base.localPasswordCompare";
    public static final String LDAP_BASE_MAIL_ATTRIBUTE_NAME = LDAP_PREFIX + "base.mailAttributeName";
    public static final String LDAP_BASE_MAIL_SUBSTITUTE = LDAP_PREFIX + "base.mailSubstitute";
    public static final String LDAP_BASE_MAIL_SUBSTITUTE_OVERRIDES_LDAP = LDAP_PREFIX + "base.mailSubstituteOverridesLdap";
    public static final String LDAP_BASE_PASSWORD = LDAP_PREFIX + "base.password";
    public static final String LDAP_BASE_PASSWORD_ATTRIBUTE_NAME = LDAP_PREFIX + "base.passwordAttributeName";
    public static final String LDAP_BASE_PASSWORD_ENCODER = LDAP_PREFIX + "base.passwordEncoder";
    public static final String LDAP_BASE_REFERRAL = LDAP_PREFIX + "base.referral";
    public static final String LDAP_BASE_SEARCH_BASE = LDAP_PREFIX + "base.searchBase";
    public static final String LDAP_BASE_SEARCH_FILTER = LDAP_PREFIX + "base.searchFilter";
    public static final String LDAP_BASE_URL = LDAP_PREFIX + "base.url";
    public static final String LDAP_BASE_USER_DN = LDAP_PREFIX + "base.userDn";
    public static final String LDAP_BASE_USER_DN_PATTERN = LDAP_PREFIX + "base.userDnPattern";
    public static final String LDAP_BASE_USER_DN_PATTERN_DELIMITER = LDAP_PREFIX + "base.userDnPatternDelimiter";
    public static final String LDAP_EMAIL_DOMAIN = LDAP_PREFIX + EMAIL_DOMAIN_ATTR;
    public static final String LDAP_EXTERNAL_GROUPS_WHITELIST = LDAP_PREFIX + "externalGroupsWhitelist";
    public static final String LDAP_GROUP_FILE_GROUPS_AS_SCOPES = "ldap/ldap-groups-as-scopes.xml";
    public static final String LDAP_GROUP_FILE_GROUPS_MAP_TO_SCOPES = "ldap/ldap-groups-map-to-scopes.xml";
    public static final String LDAP_GROUP_FILE_GROUPS_NULL_XML = "ldap/ldap-groups-null.xml";
    public static final String LDAP_GROUPS_AUTO_ADD = LDAP_PREFIX + "groups.autoAdd";
    public static final String LDAP_GROUPS_FILE = LDAP_PREFIX + "groups.file";
    public static final String LDAP_GROUPS_GROUP_ROLE_ATTRIBUTE = LDAP_PREFIX + "groups.groupRoleAttribute";
    public static final String LDAP_GROUPS_GROUP_SEARCH_FILTER = LDAP_PREFIX + "groups.groupSearchFilter";
    public static final String LDAP_GROUPS_IGNORE_PARTIAL_RESULT_EXCEPTION = LDAP_PREFIX + "groups.ignorePartialResultException";
    public static final String LDAP_GROUPS_MAX_SEARCH_DEPTH = LDAP_PREFIX + "groups.maxSearchDepth";
    public static final String LDAP_GROUPS_SEARCH_BASE = LDAP_PREFIX + "groups.searchBase";
    public static final String LDAP_GROUPS_SEARCH_SUBTREE = LDAP_PREFIX + "groups.searchSubtree";
    public static final String LDAP_PROFILE_FILE = LDAP_PREFIX + "profile.file";
    public static final String LDAP_PROFILE_FILE_SEARCH_AND_BIND = "ldap/ldap-search-and-bind.xml";
    public static final String LDAP_PROFILE_FILE_SEARCH_AND_COMPARE = "ldap/ldap-search-and-compare.xml";
    public static final String LDAP_PROFILE_FILE_SIMPLE_BIND = "ldap/ldap-simple-bind.xml";
    public static final String LDAP_SSL_SKIPVERIFICATION = LDAP_PREFIX + "ssl.skipverification";
    public static final String MAIL = "mail";

    public static final List<String> LDAP_PROPERTY_NAMES = Collections.unmodifiableList(
        Arrays.asList(
            LDAP_ATTRIBUTE_MAPPINGS,
            LDAP_BASE_LOCAL_PASSWORD_COMPARE,
            LDAP_BASE_MAIL_ATTRIBUTE_NAME,
            LDAP_BASE_MAIL_SUBSTITUTE,
            LDAP_BASE_MAIL_SUBSTITUTE_OVERRIDES_LDAP,
            LDAP_BASE_PASSWORD,
            LDAP_BASE_PASSWORD_ATTRIBUTE_NAME,
            LDAP_BASE_PASSWORD_ENCODER,
            LDAP_BASE_REFERRAL,
            LDAP_BASE_SEARCH_BASE,
            LDAP_BASE_SEARCH_FILTER,
            LDAP_BASE_URL,
            LDAP_BASE_USER_DN,
            LDAP_BASE_USER_DN_PATTERN,
            LDAP_BASE_USER_DN_PATTERN_DELIMITER,
            LDAP_EMAIL_DOMAIN,
            LDAP_EXTERNAL_GROUPS_WHITELIST,
            LDAP_GROUPS_AUTO_ADD,
            LDAP_GROUPS_FILE,
            LDAP_GROUPS_GROUP_ROLE_ATTRIBUTE,
            LDAP_GROUPS_GROUP_SEARCH_FILTER,
            LDAP_GROUPS_IGNORE_PARTIAL_RESULT_EXCEPTION,
            LDAP_GROUPS_MAX_SEARCH_DEPTH,
            LDAP_GROUPS_SEARCH_BASE,
            LDAP_GROUPS_SEARCH_SUBTREE,
            LDAP_PROFILE_FILE,
            LDAP_SSL_SKIPVERIFICATION
        )
    );

    public static final Map<String,Class<?>> LDAP_PROPERTY_TYPES = new HashMap<>();
    static {
        LDAP_PROPERTY_TYPES.put(LDAP_ATTRIBUTE_MAPPINGS, Map.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_LOCAL_PASSWORD_COMPARE, Boolean.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_MAIL_ATTRIBUTE_NAME, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_MAIL_SUBSTITUTE, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_MAIL_SUBSTITUTE_OVERRIDES_LDAP, Boolean.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_PASSWORD, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_PASSWORD_ATTRIBUTE_NAME, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_PASSWORD_ENCODER, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_REFERRAL, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_SEARCH_BASE, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_SEARCH_FILTER, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_URL, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_USER_DN, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_USER_DN_PATTERN, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_BASE_USER_DN_PATTERN_DELIMITER, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_EMAIL_DOMAIN, List.class);
        LDAP_PROPERTY_TYPES.put(LDAP_EXTERNAL_GROUPS_WHITELIST, List.class);
        LDAP_PROPERTY_TYPES.put(LDAP_GROUPS_AUTO_ADD, Boolean.class);
        LDAP_PROPERTY_TYPES.put(LDAP_GROUPS_FILE, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_GROUPS_GROUP_ROLE_ATTRIBUTE, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_GROUPS_GROUP_SEARCH_FILTER, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_GROUPS_IGNORE_PARTIAL_RESULT_EXCEPTION, Boolean.class);
        LDAP_PROPERTY_TYPES.put(LDAP_GROUPS_MAX_SEARCH_DEPTH, Integer.class);
        LDAP_PROPERTY_TYPES.put(LDAP_GROUPS_SEARCH_BASE, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_GROUPS_SEARCH_SUBTREE, Boolean.class);
        LDAP_PROPERTY_TYPES.put(LDAP_PROFILE_FILE, String.class);
        LDAP_PROPERTY_TYPES.put(LDAP_SSL_SKIPVERIFICATION, Boolean.class);
    }

    private String ldapProfileFile;
    private String baseUrl;
    private String referral;
    private Boolean skipSSLVerification;
    private String userDNPattern;
    private String userDNPatternDelimiter;

    private String bindUserDn;
    private String bindPassword;
    private String userSearchBase;
    private String userSearchFilter;

    private String passwordAttributeName;
    private String passwordEncoder;
    private Boolean localPasswordCompare;
    private String mailAttributeName = MAIL;
    private String mailSubstitute;

    private Boolean mailSubstituteOverridesLdap = false;
    private String ldapGroupFile = null;
    private String groupSearchBase;
    private String groupSearchFilter;
    private Boolean groupsIgnorePartialResults;

    private Boolean autoAddGroups = true;
    private Boolean groupSearchSubTree = true;
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
        Boolean mailSubstituteOverridesLdap,
        Boolean autoAddGroups,
        Boolean groupSearchSubTree,
        int groupMaxSearchDepth,
        Boolean skipSSLVerification) {

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
        definition.ldapProfileFile=LDAP_PROFILE_FILE_SEARCH_AND_BIND;
        definition.ldapGroupFile= LDAP_GROUP_FILE_GROUPS_MAP_TO_SCOPES;
        definition.mailSubstituteOverridesLdap = mailSubstituteOverridesLdap;
        definition.autoAddGroups = autoAddGroups;
        definition.groupSearchSubTree = groupSearchSubTree;
        definition.maxGroupSearchDepth = groupMaxSearchDepth;
        definition.skipSSLVerification = skipSSLVerification;
        return definition;
    }

    /**
     * Load a LDAP definition from the Yaml config (IdentityProviderBootstrap)
     */
    public static LdapIdentityProviderDefinition fromConfig(Map<String, Object> ldapConfig) {
        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        if (ldapConfig==null || ldapConfig.isEmpty()) {
            return definition;
        }

        if (ldapConfig.get(LDAP_EMAIL_DOMAIN)!=null) {
            definition.setEmailDomain((List<String>) ldapConfig.get(LDAP_EMAIL_DOMAIN));
        }

        if (ldapConfig.get(LDAP_EXTERNAL_GROUPS_WHITELIST)!=null) {
            definition.setExternalGroupsWhitelist((List<String>) ldapConfig.get(LDAP_EXTERNAL_GROUPS_WHITELIST));
        }

        if (ldapConfig.get(LDAP_ATTRIBUTE_MAPPINGS)!=null) {
            definition.setAttributeMappings((Map<String, Object>) ldapConfig.get(LDAP_ATTRIBUTE_MAPPINGS));
        }

        definition.setLdapProfileFile((String) ldapConfig.get(LDAP_PROFILE_FILE));

        final String profileFile = definition.getLdapProfileFile();
        if (StringUtils.hasText(profileFile)) {
            switch (profileFile) {
                case LDAP_PROFILE_FILE_SIMPLE_BIND: {
                    definition.setUserDNPattern((String) ldapConfig.get(LDAP_BASE_USER_DN_PATTERN));
                    if (ldapConfig.get(LDAP_BASE_USER_DN_PATTERN_DELIMITER) != null) {
                        definition.setUserDNPatternDelimiter((String) ldapConfig.get(LDAP_BASE_USER_DN_PATTERN_DELIMITER));
                    }
                    break;
                }
                case LDAP_PROFILE_FILE_SEARCH_AND_COMPARE:
                case LDAP_PROFILE_FILE_SEARCH_AND_BIND: {
                    definition.setBindUserDn((String) ldapConfig.get(LDAP_BASE_USER_DN));
                    definition.setBindPassword((String) ldapConfig.get(LDAP_BASE_PASSWORD));
                    definition.setUserSearchBase((String) ldapConfig.get(LDAP_BASE_SEARCH_BASE));
                    definition.setUserSearchFilter((String) ldapConfig.get(LDAP_BASE_SEARCH_FILTER));
                    break;
                }
                default:
                    break;
            }
        }

        definition.setBaseUrl((String) ldapConfig.get(LDAP_BASE_URL));
        definition.setSkipSSLVerification((Boolean) ldapConfig.get(LDAP_SSL_SKIPVERIFICATION));
        definition.setReferral((String) ldapConfig.get(LDAP_BASE_REFERRAL));
        definition.setMailSubstituteOverridesLdap((Boolean)ldapConfig.get(LDAP_BASE_MAIL_SUBSTITUTE_OVERRIDES_LDAP));
        if (StringUtils.hasText((String) ldapConfig.get(LDAP_BASE_MAIL_ATTRIBUTE_NAME))) {
            definition.setMailAttributeName((String) ldapConfig.get(LDAP_BASE_MAIL_ATTRIBUTE_NAME));
        }
        definition.setMailSubstitute((String) ldapConfig.get(LDAP_BASE_MAIL_SUBSTITUTE));
        definition.setPasswordAttributeName((String) ldapConfig.get(LDAP_BASE_PASSWORD_ATTRIBUTE_NAME));
        definition.setPasswordEncoder((String) ldapConfig.get(LDAP_BASE_PASSWORD_ENCODER));
        definition.setLocalPasswordCompare((Boolean)ldapConfig.get(LDAP_BASE_LOCAL_PASSWORD_COMPARE));
        if (StringUtils.hasText((String) ldapConfig.get(LDAP_GROUPS_FILE))) {
            definition.setLdapGroupFile((String) ldapConfig.get(LDAP_GROUPS_FILE));
        }
        if (StringUtils.hasText(definition.getLdapGroupFile()) && !LDAP_GROUP_FILE_GROUPS_NULL_XML.equals(definition.getLdapGroupFile())) {
            definition.setGroupSearchBase((String) ldapConfig.get(LDAP_GROUPS_SEARCH_BASE));
            definition.setGroupSearchFilter((String) ldapConfig.get(LDAP_GROUPS_GROUP_SEARCH_FILTER));
            definition.setGroupsIgnorePartialResults((Boolean)ldapConfig.get(LDAP_GROUPS_IGNORE_PARTIAL_RESULT_EXCEPTION));
            if (ldapConfig.get(LDAP_GROUPS_MAX_SEARCH_DEPTH) != null) {
                definition.setMaxGroupSearchDepth((Integer) ldapConfig.get(LDAP_GROUPS_MAX_SEARCH_DEPTH));
            }
            definition.setGroupSearchSubTree((Boolean) ldapConfig.get(LDAP_GROUPS_SEARCH_SUBTREE));
            definition.setAutoAddGroups((Boolean) ldapConfig.get(LDAP_GROUPS_AUTO_ADD));
            definition.setGroupRoleAttribute((String) ldapConfig.get(LDAP_GROUPS_GROUP_ROLE_ATTRIBUTE));
        }

        //if flat attributes are set in the properties
        final String LDAP_ATTR_MAP_PREFIX = LDAP_ATTRIBUTE_MAPPINGS+".";
        for (Map.Entry<String,Object> entry : ldapConfig.entrySet()) {
            if (!LDAP_PROPERTY_NAMES.contains(entry.getKey()) &&
                entry.getKey().startsWith(LDAP_ATTR_MAP_PREFIX) &&
                entry.getValue() instanceof String) {
                definition.addAttributeMapping(entry.getKey().substring(LDAP_ATTR_MAP_PREFIX.length()), entry.getValue());
            }
        }
        return definition;
    }

    @JsonIgnore
    public ConfigurableEnvironment getLdapConfigurationEnvironment() {
        Map<String,Object> properties = new HashMap<>();

        setIfNotNull(LDAP_ATTRIBUTE_MAPPINGS, getAttributeMappings(), properties);
        setIfNotNull(LDAP_BASE_LOCAL_PASSWORD_COMPARE, isLocalPasswordCompare(), properties);
        setIfNotNull(LDAP_BASE_MAIL_ATTRIBUTE_NAME, getMailAttributeName(), properties);
        setIfNotNull(LDAP_BASE_MAIL_SUBSTITUTE, getMailSubstitute(), properties);
        setIfNotNull(LDAP_BASE_MAIL_SUBSTITUTE_OVERRIDES_LDAP, isMailSubstituteOverridesLdap(), properties);
        setIfNotNull(LDAP_BASE_PASSWORD, getBindPassword(), properties);
        setIfNotNull(LDAP_BASE_PASSWORD_ATTRIBUTE_NAME, getPasswordAttributeName(), properties);
        setIfNotNull(LDAP_BASE_PASSWORD_ENCODER, getPasswordEncoder(), properties);
        setIfNotNull(LDAP_BASE_REFERRAL, getReferral(), properties);
        setIfNotNull(LDAP_BASE_SEARCH_BASE, getUserSearchBase(), properties);
        setIfNotNull(LDAP_BASE_SEARCH_FILTER, getUserSearchFilter(), properties);
        setIfNotNull(LDAP_BASE_URL, getBaseUrl(), properties);
        setIfNotNull(LDAP_BASE_USER_DN, getBindUserDn(), properties);
        setIfNotNull(LDAP_BASE_USER_DN_PATTERN, getUserDNPattern(), properties);
        setIfNotNull(LDAP_BASE_USER_DN_PATTERN_DELIMITER, getUserDNPatternDelimiter(), properties);
        setIfNotNull(LDAP_EMAIL_DOMAIN, getEmailDomain(), properties);
        setIfNotNull(LDAP_EXTERNAL_GROUPS_WHITELIST, getExternalGroupsWhitelist(), properties);
        setIfNotNull(LDAP_GROUPS_AUTO_ADD, isAutoAddGroups(), properties);
        setIfNotNull(LDAP_GROUPS_FILE, getLdapGroupFile(), properties);
        setIfNotNull(LDAP_GROUPS_GROUP_ROLE_ATTRIBUTE, getGroupRoleAttribute(), properties);
        setIfNotNull(LDAP_GROUPS_GROUP_SEARCH_FILTER, getGroupSearchFilter(), properties);
        setIfNotNull(LDAP_GROUPS_IGNORE_PARTIAL_RESULT_EXCEPTION, isGroupsIgnorePartialResults(), properties);
        setIfNotNull(LDAP_GROUPS_MAX_SEARCH_DEPTH, getMaxGroupSearchDepth(), properties);
        setIfNotNull(LDAP_GROUPS_SEARCH_BASE, getGroupSearchBase(), properties);
        setIfNotNull(LDAP_GROUPS_SEARCH_SUBTREE, isGroupSearchSubTree(), properties);
        setIfNotNull(LDAP_PROFILE_FILE, getLdapProfileFile(), properties);
        setIfNotNull(LDAP_SSL_SKIPVERIFICATION, isSkipSSLVerification(), properties);

        MapPropertySource source = new NestedMapPropertySource("ldap", properties);
        return new LdapConfigEnvironment(source);
    }

    protected void setIfNotNull(String property, Object value, Map<String,Object> map) {
        if (value!=null) {
            map.put(property, value);
        }
    }

    public String getReferral() {
        return referral;
    }

    public void setReferral(String referral) {
        this.referral = referral;
    }

    public Boolean isAutoAddGroups() {
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

    public Boolean isMailSubstituteOverridesLdap() {
        return mailSubstituteOverridesLdap==null ? false : mailSubstituteOverridesLdap;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public Boolean isGroupSearchSubTree() {
        return groupSearchSubTree;
    }

    public int getMaxGroupSearchDepth() {
        return maxGroupSearchDepth;
    }

    public Boolean isSkipSSLVerification() {
        return skipSSLVerification==null?false:skipSSLVerification;
    }

    public void setAutoAddGroups(Boolean autoAddGroups) {
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

    public void setGroupSearchSubTree(Boolean groupSearchSubTree) {
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

    public void setMailSubstituteOverridesLdap(Boolean mailSubstituteOverridesLdap) {
        this.mailSubstituteOverridesLdap = mailSubstituteOverridesLdap;
    }

    public void setMaxGroupSearchDepth(int maxGroupSearchDepth) {
        this.maxGroupSearchDepth = maxGroupSearchDepth;
    }

    public void setSkipSSLVerification(Boolean skipSSLVerification) {
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
    public Boolean isConfigured() {
        return StringUtils.hasText(getBaseUrl());
    }

    public Boolean isLocalPasswordCompare() {
        return localPasswordCompare;
    }

    public void setLocalPasswordCompare(Boolean localPasswordCompare) {
        this.localPasswordCompare = localPasswordCompare;
    }

    public String getUserDNPatternDelimiter() {
        return userDNPatternDelimiter;
    }

    public void setUserDNPatternDelimiter(String userDNPatternDelimiter) {
        this.userDNPatternDelimiter = userDNPatternDelimiter;
    }

    public Boolean isGroupsIgnorePartialResults() {
        return groupsIgnorePartialResults;
    }

    public void setGroupsIgnorePartialResults(Boolean groupsIgnorePartialResults) {
        this.groupsIgnorePartialResults = groupsIgnorePartialResults;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        LdapIdentityProviderDefinition that = (LdapIdentityProviderDefinition) o;

        if (skipSSLVerification != that.skipSSLVerification) return false;
        if (localPasswordCompare != that.localPasswordCompare) return false;
        if (mailSubstituteOverridesLdap != that.mailSubstituteOverridesLdap) return false;
        if (groupsIgnorePartialResults != that.groupsIgnorePartialResults) return false;
        if (autoAddGroups != that.autoAddGroups) return false;
        if (groupSearchSubTree != that.groupSearchSubTree) return false;
        if (maxGroupSearchDepth != that.maxGroupSearchDepth) return false;
        if (ldapProfileFile != null ? !ldapProfileFile.equals(that.ldapProfileFile) : that.ldapProfileFile != null)
            return false;
        if (baseUrl != null ? !baseUrl.equals(that.baseUrl) : that.baseUrl != null) return false;
        if (referral != null ? !referral.equals(that.referral) : that.referral != null) return false;
        if (userDNPattern != null ? !userDNPattern.equals(that.userDNPattern) : that.userDNPattern != null)
            return false;
        if (userDNPatternDelimiter != null ? !userDNPatternDelimiter.equals(that.userDNPatternDelimiter) : that.userDNPatternDelimiter != null)
            return false;
        if (bindUserDn != null ? !bindUserDn.equals(that.bindUserDn) : that.bindUserDn != null) return false;
        if (bindPassword != null ? !bindPassword.equals(that.bindPassword) : that.bindPassword != null) return false;
        if (userSearchBase != null ? !userSearchBase.equals(that.userSearchBase) : that.userSearchBase != null)
            return false;
        if (userSearchFilter != null ? !userSearchFilter.equals(that.userSearchFilter) : that.userSearchFilter != null)
            return false;
        if (passwordAttributeName != null ? !passwordAttributeName.equals(that.passwordAttributeName) : that.passwordAttributeName != null)
            return false;
        if (passwordEncoder != null ? !passwordEncoder.equals(that.passwordEncoder) : that.passwordEncoder != null)
            return false;
        if (mailAttributeName != null ? !mailAttributeName.equals(that.mailAttributeName) : that.mailAttributeName != null)
            return false;
        if (mailSubstitute != null ? !mailSubstitute.equals(that.mailSubstitute) : that.mailSubstitute != null)
            return false;
        if (ldapGroupFile != null ? !ldapGroupFile.equals(that.ldapGroupFile) : that.ldapGroupFile != null)
            return false;
        if (groupSearchBase != null ? !groupSearchBase.equals(that.groupSearchBase) : that.groupSearchBase != null)
            return false;
        if (groupSearchFilter != null ? !groupSearchFilter.equals(that.groupSearchFilter) : that.groupSearchFilter != null)
            return false;
        return !(groupRoleAttribute != null ? !groupRoleAttribute.equals(that.groupRoleAttribute) : that.groupRoleAttribute != null);

    }

    @Override
    public int hashCode() {
        return baseUrl != null ? baseUrl.hashCode() : 0;
    }

    public static class LdapConfigEnvironment extends AbstractEnvironment {
        public LdapConfigEnvironment(MapPropertySource source) {
            getPropertySources().addFirst(source);
        }
    }
}
