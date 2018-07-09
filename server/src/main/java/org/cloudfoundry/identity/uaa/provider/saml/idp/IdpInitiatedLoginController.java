/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml.idp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import static org.springframework.util.StringUtils.hasText;

@Controller
public class IdpInitiatedLoginController {

    private static final Logger log = LoggerFactory.getLogger(IdpInitiatedLoginController.class);

    private SamlServiceProviderConfigurator configurator;
    private IdpSamlAuthenticationSuccessHandler idpSamlAuthenticationSuccessHandler;

    @RequestMapping("/saml/idp/initiate")
    public void initiate(@RequestParam(value = "sp", required = false) String sp,
                         HttpServletRequest request,
                         HttpServletResponse response) {

        if (!hasText(sp)) {
            throw new ProviderNotFoundException("Missing sp request parameter. sp parameter must be a valid and configured entity ID");
        }
        log.debug(String.format("IDP is initiating authentication request to SP[%s]", sp));
        Optional<SamlServiceProviderHolder> holder = configurator.getSamlServiceProviders().stream().filter(serviceProvider -> sp.equals(serviceProvider.getSamlServiceProvider().getEntityId())).findFirst();
        if (!holder.isPresent()) {
            log.debug(String.format("SP[%s] was not found, aborting saml response", sp));
            throw new ProviderNotFoundException("Invalid sp entity ID. sp parameter must be a valid and configured entity ID");
        }
        if (!holder.get().getSamlServiceProvider().isActive()) {
            log.debug(String.format("SP[%s] is disabled, aborting saml response", sp));
            throw new ProviderNotFoundException("Service provider is disabled.");
        }
        if (!holder.get().getSamlServiceProvider().getConfig().isEnableIdpInitiatedSso()) {
            log.debug(String.format("SP[%s] initiated login is disabled, aborting saml response", sp));
            throw new ProviderNotFoundException("IDP initiated login is disabled for this service provider.");
        }

        String nameId = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        try {
            String assertionLocation = "";
            log.debug(String.format("IDP is sending assertion for SP[%s] to %s", sp, assertionLocation));
        } catch (Exception  e) {
            log.debug(String.format("IDP is unable to process assertion for SP[%s]", sp), e);
            throw new ProviderNotFoundException("Unable to process SAML assertion. Response not sent.");
        }
    }




    @ExceptionHandler
    public String handleException(AuthenticationException ae, HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(400);
        request.setAttribute("saml_error", ae.getMessage());
        return "external_auth_error";
    }
}
