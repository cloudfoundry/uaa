/*
 * *****************************************************************************
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

import lombok.Data;
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
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.springframework.beans.factory.InitializingBean;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import static java.util.Objects.nonNull;
import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

@Data
public class IdentityZoneConfigurationBootstrap implements InitializingBean {

    private ClientSecretPolicy clientSecretPolicy;
    private TokenPolicy tokenPolicy;

    private final IdentityZoneProvisioning provisioning;
    private boolean selfServiceLinksEnabled = true;
    private String homeRedirect;
    private Map<String, Object> selfServiceLinks;
    private List<String> logoutRedirectWhitelist;
    private String logoutRedirectParameterName;
    private String logoutDefaultRedirectUrl;
    private boolean logoutDisableRedirectParameter = true;
    private List<Prompt> prompts;
    private String defaultIdentityProvider;

    private String samlSpPrivateKey;
    private String samlSpPrivateKeyPassphrase;
    private String samlSpCertificate;
    private boolean disableSamlInResponseToCheck;
    private boolean samlWantAssertionSigned = true;
    private boolean samlRequestSigned = true;

    private Map<String, Map<String, String>> samlKeys;
    private String activeKeyId;

    private boolean idpDiscoveryEnabled;
    private boolean accountChooserEnabled;

    private UserConfig defaultUserConfig;

    private IdentityZoneValidator validator = (config, mode) -> config;
    private Map<String, Object> branding;

    public IdentityZoneConfigurationBootstrap(IdentityZoneProvisioning provisioning) {
        this.provisioning = provisioning;
    }

    @Override
    public void afterPropertiesSet() throws InvalidIdentityZoneDetailsException {
        IdentityZone identityZone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        definition.setClientSecretPolicy(clientSecretPolicy);
        definition.getLinks().getSelfService().setSelfServiceLinksEnabled(selfServiceLinksEnabled);
        definition.getLinks().setHomeRedirect(homeRedirect);
        definition.getSamlConfig().setCertificate(samlSpCertificate);
        definition.getSamlConfig().setPrivateKey(samlSpPrivateKey);
        definition.getSamlConfig().setPrivateKeyPassword(samlSpPrivateKeyPassphrase);
        definition.getSamlConfig().setDisableInResponseToCheck(disableSamlInResponseToCheck);
        definition.getSamlConfig().setWantAssertionSigned(samlWantAssertionSigned);
        definition.getSamlConfig().setRequestSigned(samlRequestSigned);
        definition.setIdpDiscoveryEnabled(idpDiscoveryEnabled);
        definition.setAccountChooserEnabled(accountChooserEnabled);
        definition.setDefaultIdentityProvider(defaultIdentityProvider);
        definition.setUserConfig(defaultUserConfig);

        samlKeys = ofNullable(samlKeys).orElse(Map.of());
        for (Map.Entry<String, Map<String, String>> entry : samlKeys.entrySet()) {
            SamlKey samlKey = new SamlKey(entry.getValue().get("key"), entry.getValue().get("passphrase"), entry.getValue().get("certificate"));
            definition.getSamlConfig().addKey(ofNullable(entry.getKey()).orElseThrow(() -> new InvalidIdentityZoneDetailsException("SAML key id must not be null.", null)).toLowerCase(Locale.ROOT), samlKey);
        }
        definition.getSamlConfig().setActiveKeyId(this.activeKeyId);

        if (selfServiceLinks != null) {
            String signup = (String) selfServiceLinks.get("signup");
            String passwd = (String) selfServiceLinks.get("passwd");
            if (hasText(signup)) {
                definition.getLinks().getSelfService().setSignup(signup);
            }
            if (hasText(passwd)) {
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

        identityZone.setConfig(definition);

        identityZone = validator.validate(identityZone, IdentityZoneValidator.Mode.MODIFY);
        provisioning.update(identityZone);
    }

    public IdentityZoneConfigurationBootstrap setSamlKeys(Map<String, Map<String, String>> samlKeys) {
        this.samlKeys = samlKeys;
        return this;
    }

    public IdentityZoneConfigurationBootstrap setActiveKeyId(String activeKeyId) {
        this.activeKeyId = activeKeyId != null ? activeKeyId.toLowerCase(Locale.ROOT) : null;
        return this;
    }
}
