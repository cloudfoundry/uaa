/*
 * ******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition.PROVIDER_DESCRIPTION;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_PREFIX;

public final class LdapUtils {

    private LdapUtils() {
    }

    public static ConfigurableEnvironment getLdapConfigurationEnvironment(LdapIdentityProviderDefinition definition) {
        Assert.notNull(definition, "must not be null");

        Map<String, Object> properties = new HashMap<>();

        setIfNotNull(LdapIdentityProviderDefinition.LDAP_ATTRIBUTE_MAPPINGS, definition.getAttributeMappings(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_LOCAL_PASSWORD_COMPARE, definition.isLocalPasswordCompare(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_MAIL_ATTRIBUTE_NAME, definition.getMailAttributeName(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_MAIL_SUBSTITUTE, definition.getMailSubstitute(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_MAIL_SUBSTITUTE_OVERRIDES_LDAP, definition.isMailSubstituteOverridesLdap(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_PASSWORD, definition.getBindPassword(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_PASSWORD_ATTRIBUTE_NAME, definition.getPasswordAttributeName(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_PASSWORD_ENCODER, definition.getPasswordEncoder(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_REFERRAL, definition.getReferral(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_SEARCH_BASE, definition.getUserSearchBase(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_SEARCH_FILTER, definition.getUserSearchFilter(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_URL, definition.getBaseUrl(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_USER_DN, definition.getBindUserDn(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_USER_DN_PATTERN, definition.getUserDNPattern(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_BASE_USER_DN_PATTERN_DELIMITER, definition.getUserDNPatternDelimiter(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_EMAIL_DOMAIN, definition.getEmailDomain(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_EXTERNAL_GROUPS_WHITELIST, definition.getExternalGroupsWhitelist(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_GROUPS_AUTO_ADD, definition.isAutoAddGroups(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_GROUPS_FILE, definition.getLdapGroupFile(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_GROUPS_GROUP_ROLE_ATTRIBUTE, definition.getGroupRoleAttribute(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_GROUPS_GROUP_SEARCH_FILTER, definition.getGroupSearchFilter(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_GROUPS_IGNORE_PARTIAL_RESULT_EXCEPTION, definition.isGroupsIgnorePartialResults(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_GROUPS_MAX_SEARCH_DEPTH, definition.getMaxGroupSearchDepth(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_GROUPS_SEARCH_BASE, definition.getGroupSearchBase(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_GROUPS_SEARCH_SUBTREE, definition.isGroupSearchSubTree(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_PROFILE_FILE, definition.getLdapProfileFile(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_SSL_SKIPVERIFICATION, definition.isSkipSSLVerification(), properties);
        setIfNotNull(LdapIdentityProviderDefinition.LDAP_SSL_TLS, definition.getTlsConfiguration(), properties);
        setIfNotNull("ldap.addShadowUserOnLogin", definition.isAddShadowUserOnLogin(), properties);

        MapPropertySource source = new NestedMapPropertySource("ldap", properties);
        return new LdapIdentityProviderDefinition.LdapConfigEnvironment(source);
    }

    private static void setIfNotNull(String property, Object value, Map<String, Object> map) {
        if (value != null) {
            map.put(property, value);
        }
    }

    /**
     * Load a LDAP definition from the Yaml config (IdentityProviderBootstrap)
     */
    public static LdapIdentityProviderDefinition fromConfig(Map<String, Object> ldapConfig) {
        Assert.notNull(ldapConfig, "must not be null");

        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        if (ldapConfig == null || ldapConfig.isEmpty()) {
            return definition;
        }

        if (ldapConfig.get(LdapIdentityProviderDefinition.LDAP_STORE_CUSTOM_ATTRIBUTES) != null) {
            definition.setStoreCustomAttributes((boolean) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_STORE_CUSTOM_ATTRIBUTES));
        }

        if (ldapConfig.get(LdapIdentityProviderDefinition.LDAP_EMAIL_DOMAIN) != null) {
            definition.setEmailDomain((List<String>) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_EMAIL_DOMAIN));
        }

        if (ldapConfig.get(LdapIdentityProviderDefinition.LDAP_EXTERNAL_GROUPS_WHITELIST) != null) {
            definition.setExternalGroupsWhitelist((List<String>) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_EXTERNAL_GROUPS_WHITELIST));
        }

        if (ldapConfig.get(LdapIdentityProviderDefinition.LDAP_ATTRIBUTE_MAPPINGS) != null) {
            definition.setAttributeMappings((Map<String, Object>) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_ATTRIBUTE_MAPPINGS));
        }

        if (ldapConfig.get("ldap.addShadowUserOnLogin") != null) {
            definition.setAddShadowUserOnLogin((boolean) ldapConfig.get("ldap.addShadowUserOnLogin"));
        }

        definition.setLdapProfileFile((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_PROFILE_FILE));

        final String profileFile = definition.getLdapProfileFile();
        if (StringUtils.hasText(profileFile)) {
            switch (profileFile) {
                case LdapIdentityProviderDefinition.LDAP_PROFILE_FILE_SIMPLE_BIND: {
                    definition.setUserDNPattern((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_USER_DN_PATTERN));
                    if (ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_USER_DN_PATTERN_DELIMITER) != null) {
                        definition.setUserDNPatternDelimiter((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_USER_DN_PATTERN_DELIMITER));
                    }
                    break;
                }
                case LdapIdentityProviderDefinition.LDAP_PROFILE_FILE_SEARCH_AND_COMPARE:
                case LdapIdentityProviderDefinition.LDAP_PROFILE_FILE_SEARCH_AND_BIND: {
                    definition.setBindUserDn((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_USER_DN));
                    definition.setBindPassword((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_PASSWORD));
                    definition.setUserSearchBase((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_SEARCH_BASE));
                    definition.setUserSearchFilter((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_SEARCH_FILTER));
                    break;
                }
                default:
                    break;
            }
        }

        definition.setBaseUrl((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_URL));
        definition.setSkipSSLVerification((Boolean) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_SSL_SKIPVERIFICATION));
        definition.setTlsConfiguration((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_SSL_TLS));
        definition.setReferral((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_REFERRAL));
        definition.setMailSubstituteOverridesLdap((Boolean) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_MAIL_SUBSTITUTE_OVERRIDES_LDAP));
        if (StringUtils.hasText((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_MAIL_ATTRIBUTE_NAME))) {
            definition.setMailAttributeName((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_MAIL_ATTRIBUTE_NAME));
        }
        definition.setMailSubstitute((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_MAIL_SUBSTITUTE));
        definition.setPasswordAttributeName((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_PASSWORD_ATTRIBUTE_NAME));
        definition.setPasswordEncoder((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_PASSWORD_ENCODER));
        definition.setLocalPasswordCompare((Boolean) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_BASE_LOCAL_PASSWORD_COMPARE));
        if (StringUtils.hasText((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_FILE))) {
            definition.setLdapGroupFile((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_FILE));
        }
        if (StringUtils.hasText(definition.getLdapGroupFile()) && !LdapIdentityProviderDefinition.LDAP_GROUP_FILE_GROUPS_NULL_XML.equals(definition.getLdapGroupFile())) {
            definition.setGroupSearchBase((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_SEARCH_BASE));
            definition.setGroupSearchFilter((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_GROUP_SEARCH_FILTER));
            definition.setGroupsIgnorePartialResults((Boolean) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_IGNORE_PARTIAL_RESULT_EXCEPTION));
            if (ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_MAX_SEARCH_DEPTH) != null) {
                definition.setMaxGroupSearchDepth((Integer) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_MAX_SEARCH_DEPTH));
            }
            definition.setGroupSearchSubTree((Boolean) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_SEARCH_SUBTREE));
            definition.setAutoAddGroups((Boolean) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_AUTO_ADD));
            definition.setGroupRoleAttribute((String) ldapConfig.get(LdapIdentityProviderDefinition.LDAP_GROUPS_GROUP_ROLE_ATTRIBUTE));
        }

        //if flat attributes are set in the properties
        final String ldapAttrMapPrefix = LdapIdentityProviderDefinition.LDAP_ATTRIBUTE_MAPPINGS + ".";
        for (Map.Entry<String, Object> entry : ldapConfig.entrySet()) {
            if (!LdapIdentityProviderDefinition.LDAP_PROPERTY_NAMES.contains(entry.getKey()) &&
                    entry.getKey().startsWith(ldapAttrMapPrefix) &&
                    entry.getValue() instanceof String) {
                definition.addAttributeMapping(entry.getKey().substring(ldapAttrMapPrefix.length()), entry.getValue());
            }
        }

        if (ldapConfig.get(LDAP_PREFIX + PROVIDER_DESCRIPTION) != null && ldapConfig.get(LDAP_PREFIX + PROVIDER_DESCRIPTION) instanceof String) {
            definition.setProviderDescription((String) ldapConfig.get(LDAP_PREFIX + PROVIDER_DESCRIPTION));
        }

        return definition;
    }
}
