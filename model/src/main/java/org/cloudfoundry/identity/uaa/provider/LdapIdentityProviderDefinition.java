/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.util.*;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LdapIdentityProviderDefinition extends ExternalIdentityProviderDefinition {
    public static final String LDAP_TLS_NONE = "none";
    public static final String LDAP_TLS_SIMPLE = "simple";
    public static final String LDAP_TLS_EXTERNAL = "external";

    public static final String LDAP = OriginKeys.LDAP;
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
    public static final String LDAP_STORE_CUSTOM_ATTRIBUTES = LDAP_PREFIX + STORE_CUSTOM_ATTRIBUTES_NAME;
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
    public static final String LDAP_SSL_TLS = LDAP_PREFIX + "ssl.tls";
    public static final String MAIL = "mail";

    public static final List<String> VALID_PROFILE_FILES =
            List.of("ldap/ldap-search-and-bind.xml", "ldap/ldap-search-and-compare.xml", "ldap/ldap-simple-bind.xml");

    public static final List<String> VALID_GROUP_FILES =
            List.of("ldap/ldap-groups-as-scopes.xml", "ldap/ldap-groups-map-to-scopes.xml", "ldap/ldap-groups-null.xml", "ldap/ldap-groups-populator.xml");


    public static final List<String> LDAP_PROPERTY_NAMES = List.of(LDAP_ATTRIBUTE_MAPPINGS, LDAP_BASE_LOCAL_PASSWORD_COMPARE, LDAP_BASE_MAIL_ATTRIBUTE_NAME, LDAP_BASE_MAIL_SUBSTITUTE, LDAP_BASE_MAIL_SUBSTITUTE_OVERRIDES_LDAP, LDAP_BASE_PASSWORD, LDAP_BASE_PASSWORD_ATTRIBUTE_NAME, LDAP_BASE_PASSWORD_ENCODER, LDAP_BASE_REFERRAL, LDAP_BASE_SEARCH_BASE, LDAP_BASE_SEARCH_FILTER, LDAP_BASE_URL, LDAP_BASE_USER_DN, LDAP_BASE_USER_DN_PATTERN, LDAP_BASE_USER_DN_PATTERN_DELIMITER, LDAP_EMAIL_DOMAIN, LDAP_EXTERNAL_GROUPS_WHITELIST, LDAP_GROUPS_AUTO_ADD, LDAP_GROUPS_FILE, LDAP_GROUPS_GROUP_ROLE_ATTRIBUTE, LDAP_GROUPS_GROUP_SEARCH_FILTER, LDAP_GROUPS_IGNORE_PARTIAL_RESULT_EXCEPTION, LDAP_GROUPS_MAX_SEARCH_DEPTH, LDAP_GROUPS_SEARCH_BASE, LDAP_GROUPS_SEARCH_SUBTREE, LDAP_PROFILE_FILE, LDAP_SSL_SKIPVERIFICATION, LDAP_SSL_TLS);

    public static final Map<String, Class<?>> LDAP_PROPERTY_TYPES = new HashMap<>();

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
        LDAP_PROPERTY_TYPES.put(LDAP_SSL_TLS, String.class);
    }

    private String ldapProfileFile;
    private String baseUrl;
    private String referral;
    private Boolean skipSSLVerification;
    private String userDNPattern;
    private String userDNPatternDelimiter;

    private String bindUserDn;
    private Object bindPassword;
    private String userSearchBase;
    private String userSearchFilter;

    private String passwordAttributeName;
    private String passwordEncoder;
    private Boolean localPasswordCompare;
    private String mailAttributeName = MAIL;
    private String mailSubstitute;

    private Boolean mailSubstituteOverridesLdap = false;
    private String ldapGroupFile;
    private String groupSearchBase;
    private String groupSearchFilter;
    private Boolean groupsIgnorePartialResults;

    private Boolean autoAddGroups = true;
    private Boolean groupSearchSubTree = true;
    private int maxGroupSearchDepth = 10;
    private String groupRoleAttribute;

    private String tlsConfiguration = LDAP_TLS_NONE;

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
        definition.ldapProfileFile = LDAP_PROFILE_FILE_SEARCH_AND_BIND;
        definition.ldapGroupFile = LDAP_GROUP_FILE_GROUPS_MAP_TO_SCOPES;
        definition.mailSubstituteOverridesLdap = mailSubstituteOverridesLdap;
        definition.autoAddGroups = autoAddGroups;
        definition.groupSearchSubTree = groupSearchSubTree;
        definition.maxGroupSearchDepth = groupMaxSearchDepth;
        definition.skipSSLVerification = skipSSLVerification;
        return definition;
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

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String getBindPassword() {
        return (String) bindPassword;
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
        return mailSubstituteOverridesLdap == null ? false : mailSubstituteOverridesLdap;
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
        return skipSSLVerification == null ? false : skipSSLVerification;
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
        if (ldapGroupFile != null && !VALID_GROUP_FILES.contains(ldapGroupFile)) {
            throw new IllegalArgumentException("Invalid profile file:" + ldapGroupFile);
        }
        this.ldapGroupFile = ldapGroupFile;
    }

    public void setLdapProfileFile(String ldapProfileFile) {
        if (ldapProfileFile != null && !VALID_PROFILE_FILES.contains(ldapProfileFile)) {
            throw new IllegalArgumentException("Invalid profile file:" + ldapProfileFile);
        }
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
        if (passwordEncoder == null || "org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator".equals(passwordEncoder)) {
            this.passwordEncoder = passwordEncoder;
        } else {
            throw new IllegalArgumentException("Unknown encoder:" + passwordEncoder);
        }
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

    public String getTlsConfiguration() {
        return tlsConfiguration;
    }

    public void setTlsConfiguration(String tlsConfiguration) {
        if (tlsConfiguration == null) {
            tlsConfiguration = LDAP_TLS_NONE;
        }
        switch (tlsConfiguration) {
            case LDAP_TLS_NONE:
            case LDAP_TLS_SIMPLE:
            case LDAP_TLS_EXTERNAL:
                this.tlsConfiguration = tlsConfiguration;
                break;
            default:
                throw new IllegalArgumentException(tlsConfiguration);
        }

    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }

        LdapIdentityProviderDefinition that = (LdapIdentityProviderDefinition) o;

        if (maxGroupSearchDepth != that.maxGroupSearchDepth) {
            return false;
        }
        if (!Objects.equals(ldapProfileFile, that.ldapProfileFile)) {
            return false;
        }
        if (!Objects.equals(baseUrl, that.baseUrl)) {
            return false;
        }
        if (!Objects.equals(referral, that.referral)) {
            return false;
        }
        if (!Objects.equals(userDNPattern, that.userDNPattern)) {
            return false;
        }
        if (!Objects.equals(userDNPatternDelimiter, that.userDNPatternDelimiter)) {
            return false;
        }
        if (!Objects.equals(bindUserDn, that.bindUserDn)) {
            return false;
        }
        if (!Objects.equals(bindPassword, that.bindPassword)) {
            return false;
        }
        if (!Objects.equals(userSearchBase, that.userSearchBase)) {
            return false;
        }
        if (!Objects.equals(userSearchFilter, that.userSearchFilter)) {
            return false;
        }
        if (!Objects.equals(passwordAttributeName, that.passwordAttributeName)) {
            return false;
        }
        if (!Objects.equals(passwordEncoder, that.passwordEncoder)) {
            return false;
        }
        if (!Objects.equals(localPasswordCompare, that.localPasswordCompare)) {
            return false;
        }
        if (!Objects.equals(mailAttributeName, that.mailAttributeName)) {
            return false;
        }
        if (!Objects.equals(mailSubstitute, that.mailSubstitute)) {
            return false;
        }
        if (!Objects.equals(mailSubstituteOverridesLdap, that.mailSubstituteOverridesLdap)) {
            return false;
        }
        if (!Objects.equals(ldapGroupFile, that.ldapGroupFile)) {
            return false;
        }
        if (!Objects.equals(groupSearchBase, that.groupSearchBase)) {
            return false;
        }
        if (!Objects.equals(groupSearchFilter, that.groupSearchFilter)) {
            return false;
        }
        if (!Objects.equals(groupsIgnorePartialResults, that.groupsIgnorePartialResults)) {
            return false;
        }
        if (!Objects.equals(autoAddGroups, that.autoAddGroups)) {
            return false;
        }
        if (!Objects.equals(groupSearchSubTree, that.groupSearchSubTree)) {
            return false;
        }
        return Objects.equals(groupRoleAttribute, that.groupRoleAttribute);

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (baseUrl != null ? baseUrl.hashCode() : 0);
        return result;
    }

    public static class LdapConfigEnvironment extends AbstractEnvironment {
        public LdapConfigEnvironment(MapPropertySource source) {
            getPropertySources().addFirst(source);
        }
    }
}
