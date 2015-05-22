/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TokenRevocationEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());
    private WebResponseExceptionTranslator exceptionTranslator = new DefaultWebResponseExceptionTranslator();
    private final ScimUserProvisioning userProvisioning;
    private final MultitenantJdbcClientDetailsService clientDetailsService;
    private final RandomValueStringGenerator generator = new RandomValueStringGenerator(8);

    public TokenRevocationEndpoint(MultitenantJdbcClientDetailsService clientDetailsService, ScimUserProvisioning userProvisioning) {
        this.clientDetailsService = clientDetailsService;
        this.userProvisioning = userProvisioning;
    }

    @RequestMapping("/oauth/token/revoke/user/{userId}")
    public void revokeTokensForUser(@PathVariable String userId) {
        logger.debug("Revoking tokens for user: "+userId);
        ScimUser user = userProvisioning.retrieve(userId);
        user.setSalt(generator.generate());
        userProvisioning.update(userId, user);
        logger.debug("Tokens revoked for user: "+userId);
    }

    @RequestMapping("/oauth/token/revoke/user/{clientId}")
    public void revokeTokensForClient(@PathVariable String clientId) {
        logger.debug("Revoking tokens for client: " + clientId);
        BaseClientDetails client = (BaseClientDetails)clientDetailsService.loadClientByClientId(clientId);
        client.addAdditionalInformation(ClientConstants.TOKEN_SALT,generator.generate());
        clientDetailsService.updateClientDetails(client);
        logger.debug("Tokens revoked for client: " + clientId);
    }

    @ExceptionHandler(ScimResourceNotFoundException.class)
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
        InvalidTokenException e404 = new InvalidTokenException("Resource not found") {
            @Override
            public int getHttpErrorCode() {
                return 404;
            }
        };
        return exceptionTranslator.translate(e404);
    }
}
