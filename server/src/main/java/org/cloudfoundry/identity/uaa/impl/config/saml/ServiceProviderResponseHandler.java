/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.impl.config.saml;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;

public class ServiceProviderResponseHandler  {

    private static Log logger = LogFactory.getLog(ServiceProviderResponseHandler.class);

    protected Object handleError(Exception exception, HttpServletRequest request, HttpServletResponse response) {
        String message = getErrorMessage(exception);
        AuthenticationException auth = new AuthenticationServiceException(message, exception);
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, auth);
        try {
            request
                .getServletContext()
                .getRequestDispatcher("/saml_error")
                .forward(request, response);
        } catch (ServletException | IOException e) {
            logger.debug("Unable to forward to saml error page", e);
            throw auth;
        }
        return null;
    }

    private String getErrorMessage(Exception exception) {
        return exception.getMessage();
    }
}
