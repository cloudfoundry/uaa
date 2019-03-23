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

package org.cloudfoundry.identity.uaa.provider.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.storage.SAMLMessageStorageFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class SamlSessionStorageFactory implements SAMLMessageStorageFactory {

    private static Logger logger = LoggerFactory.getLogger(SamlSessionStorageFactory.class);

    public static final String SAML_REQUEST_DATA = SamlMessageStorage.class.getName() + ".saml.requests";

    @Override
    public synchronized SAMLMessageStorage getMessageStorage(HttpServletRequest request) {
        if (IdentityZoneHolder.get().getConfig().getSamlConfig().isDisableInResponseToCheck()) {
            //add the ability to disable inResponseTo check
            //https://docs.spring.io/spring-security-saml/docs/current/reference/html/chapter-troubleshooting.html
            return null;
        }
        HttpSession session = request.getSession(true);
        if (session.getAttribute(SAML_REQUEST_DATA) == null) {
            session.setAttribute(SAML_REQUEST_DATA, new SamlMessageStorage());
        }
        logger.debug("Returning SAML message factory for session ID:"+session.getId());
        return (SAMLMessageStorage) session.getAttribute(SAML_REQUEST_DATA);
    }
}
