/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator;
import org.cloudfoundry.identity.uaa.zone.InvalidIdentityZoneDetailsException;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.springframework.beans.factory.InitializingBean;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.util.Collections.EMPTY_MAP;
import static java.util.Objects.nonNull;
import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class IdentityZoneConfigurationBootstrap implements InitializingBean {

    private ClientSecretPolicy clientSecretPolicy;
    private TokenPolicy tokenPolicy;
    private IdentityZoneProvisioning provisioning;
    private boolean selfServiceCreateAccountEnabled = true;
    private boolean selfServiceResetPasswordEnabled = true;
    private String homeRedirect = null;
    private Map<String,Object> selfServiceLinks;
    private boolean mfaEnabled;
    private String mfaProviderName;
    private List<String> logoutRedirectWhitelist;
    private SignatureAlgorithm samlSignatureAlgorithm;
    private String logoutRedirectParameterName;
    private String logoutDefaultRedirectUrl;
    private boolean logoutDisableRedirectParameter = true;
    private List<Prompt> prompts;
    private String defaultIdentityProvider;

    private String samlSpPrivateKey;
    private String samlSpPrivateKeyPassphrase;
    private String samlSpCertificate;
    private boolean disableSamlInResponseToCheck = false;

    private Map<String, Map<String, String>> samlKeys;
    private String activeKeyId;

    private boolean idpDiscoveryEnabled = false;

    private boolean accountChooserEnabled;

    private Collection<String> defaultUserGroups;

    private IdentityZoneValidator validator = (config, mode) -> config;
    private Map<String, Object> branding;

    public void setValidator(IdentityZoneValidator validator) {
        this.validator = validator;
    }

    public IdentityZoneConfigurationBootstrap(IdentityZoneProvisioning provisioning) {
        this.provisioning = provisioning;
    }

    @Override
    public void afterPropertiesSet() throws InvalidIdentityZoneDetailsException {
        IdentityZone identityZone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        definition.setClientSecretPolicy(clientSecretPolicy);
        definition.getLinks().getSelfService().setSelfServiceCreateAccountEnabled(selfServiceCreateAccountEnabled);
        definition.getLinks().getSelfService().setSelfServiceResetPasswordEnabled(selfServiceResetPasswordEnabled);
        definition.getLinks().setHomeRedirect(homeRedirect);
        definition.getSamlConfig().setCertificate(samlSpCertificate);
        definition.getSamlConfig().setPrivateKey(samlSpPrivateKey);
        definition.getSamlConfig().setPrivateKeyPassword(samlSpPrivateKeyPassphrase);
        definition.getSamlConfig().setDisableInResponseToCheck(disableSamlInResponseToCheck);
        definition.getSamlConfig().setSignatureAlgorithm(samlSignatureAlgorithm);
        definition.setIdpDiscoveryEnabled(idpDiscoveryEnabled);
        definition.setAccountChooserEnabled(accountChooserEnabled);
        definition.getMfaConfig().setEnabled(mfaEnabled);
        definition.getMfaConfig().setProviderName(mfaProviderName);
        definition.setDefaultIdentityProvider(defaultIdentityProvider);

        samlKeys = ofNullable(samlKeys).orElse(EMPTY_MAP);
        for (Map.Entry<String, Map<String,String>> entry : samlKeys.entrySet()) {
            SamlKey samlKey = new SamlKey(entry.getValue().get("key"), entry.getValue().get("passphrase"), entry.getValue().get("certificate"));
            definition.getSamlConfig().addKey(entry.getKey(), samlKey);
        }
        definition.getSamlConfig().setActiveKeyId(this.activeKeyId);

        if (selfServiceLinks!=null) {
            String signup = (String)selfServiceLinks.get("signup");
            String passwd = (String)selfServiceLinks.get("passwd");
            if (hasText(signup)) {
                definition.getLinks().getSelfService().setSignup(signup);
            }
            if ((passwd) != null) {
                definition.getLinks().getSelfService().setPasswd(passwd);
            }
        }
        if (nonNull(logoutRedirectWhitelist)) {
            definition.getLinks().getLogout().setWhitelist(logoutRedirectWhitelist);
        }
        if (hasText(logoutRedirectParameterName)) {
            definition.getLinks().getLogout().setRedirectParameterName(logoutRedirectParameterName);
        }
        if (hasText(logoutDefaultRedirectUrl)) {
            definition.getLinks().getLogout().setRedirectUrl(logoutDefaultRedirectUrl);
        }
        definition.getLinks().getLogout().setDisableRedirectParameter(logoutDisableRedirectParameter);
        if (nonNull(prompts)) {
            definition.setPrompts(prompts);
        }

        BrandingInformation brandingInfo = JsonUtils.convertValue(branding, BrandingInformation.class);
        definition.setBranding(brandingInfo);

        if (defaultUserGroups!=null) {
            definition.getUserConfig().setDefaultGroups(new LinkedList<>(defaultUserGroups));
        }


        identityZone.setConfig(definition);

        identityZone = validator.validate(identityZone, IdentityZoneValidator.Mode.MODIFY);
        provisioning.update(identityZone);
    }

    public void setClientSecretPolicy(ClientSecretPolicy clientSecretPolicy) {
        this.clientSecretPolicy = clientSecretPolicy;
    }

    public void setMfaEnabled(boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public void setMfaProviderName(String mfaProviderName) {
        this.mfaProviderName = mfaProviderName;
    }

    public String getMfaProviderName() {
        return mfaProviderName;
    }

    public boolean isMfaEnabled()  {
        return mfaEnabled;
    }

    public IdentityZoneConfigurationBootstrap setSamlKeys(Map<String, Map<String, String>> samlKeys) {
        this.samlKeys = samlKeys;
        return this;
    }

    public IdentityZoneConfigurationBootstrap setActiveKeyId(String activeKeyId) {
        this.activeKeyId = activeKeyId;
        return this;
    }

    public void setTokenPolicy(TokenPolicy tokenPolicy) {
        this.tokenPolicy = tokenPolicy;
    }

    public void setSelfServiceCreateAccountEnabled(boolean selfServiceCreateAccountEnabled) {
        this.selfServiceCreateAccountEnabled = selfServiceCreateAccountEnabled;
    }

    public void setSelfServiceResetPasswordEnabled(boolean selfServiceResetPasswordEnabled) {
        this.selfServiceResetPasswordEnabled = selfServiceResetPasswordEnabled;
    }

    public void setHomeRedirect(String homeRedirect) {
        this.homeRedirect = homeRedirect;
    }

    public String getHomeRedirect() {
        return homeRedirect;
    }

    public void setSelfServiceLinks(Map<String, Object> links) {
        this.selfServiceLinks = links;
    }

    public void setLogoutDefaultRedirectUrl(String logoutDefaultRedirectUrl) {
        this.logoutDefaultRedirectUrl = logoutDefaultRedirectUrl;
    }

    public void setLogoutDisableRedirectParameter(boolean logoutDisableRedirectParameter) {
        this.logoutDisableRedirectParameter = logoutDisableRedirectParameter;
    }

    public void setLogoutRedirectParameterName(String logoutRedirectParameterName) {
        this.logoutRedirectParameterName = logoutRedirectParameterName;
    }

    public void setLogoutRedirectWhitelist(List<String> logoutRedirectWhitelist) {
        this.logoutRedirectWhitelist = logoutRedirectWhitelist;
    }

    public void setPrompts(List<Prompt> prompts) {
        this.prompts = prompts;
    }

    public void setDefaultIdentityProvider(String defaultIdentityProvider) {
        this.defaultIdentityProvider = defaultIdentityProvider;
    }

    public void setSamlSpCertificate(String samlSpCertificate) {
        this.samlSpCertificate = samlSpCertificate;
    }

    public void setSamlSpPrivateKey(String samlSpPrivateKey) {
        this.samlSpPrivateKey = samlSpPrivateKey;
    }

    public void setSamlSpPrivateKeyPassphrase(String samlSpPrivateKeyPassphrase) {
        this.samlSpPrivateKeyPassphrase = samlSpPrivateKeyPassphrase;
    }

    public boolean isIdpDiscoveryEnabled() {
        return idpDiscoveryEnabled;
    }

    public void setIdpDiscoveryEnabled(boolean idpDiscoveryEnabled) {
        this.idpDiscoveryEnabled = idpDiscoveryEnabled;
    }

    public boolean isAccountChooserEnabled() {
        return accountChooserEnabled;
    }

    public void setAccountChooserEnabled(boolean accountChooserEnabled) {
        this.accountChooserEnabled = accountChooserEnabled;
    }

    public void setBranding(Map<String, Object> branding) {
        this.branding = branding;
    }

    public Map<String, Object> getBranding() {
        return branding;
    }

    public void setDefaultUserGroups(Collection<String> defaultUserGroups) {
        this.defaultUserGroups = defaultUserGroups;
    }

    public void setSamlSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.samlSignatureAlgorithm = signatureAlgorithm;
    }
    public boolean isDisableSamlInResponseToCheck() {
        return disableSamlInResponseToCheck;
    }

    public void setDisableSamlInResponseToCheck(boolean disableSamlInResponseToCheck) {
        this.disableSamlInResponseToCheck = disableSamlInResponseToCheck;
    }
}
