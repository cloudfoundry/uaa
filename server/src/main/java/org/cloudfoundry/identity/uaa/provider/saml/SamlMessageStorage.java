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
import org.opensaml.xml.XMLObject;
import org.springframework.security.saml.storage.SAMLMessageStorage;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class SamlMessageStorage implements SAMLMessageStorage {

    private static Logger logger = LoggerFactory.getLogger(SamlMessageStorage.class);
    private ConcurrentMap<String, XMLObject> messages = new ConcurrentHashMap<>();

    @Override
    public void storeMessage(String messageId, XMLObject message) {
        logger.debug(String.format("Storing SAML message with ID:%s for subdomain:%s", messageId, IdentityZoneHolder.get().getSubdomain()));
        XMLObject previous = messages.put(messageId, message);
        if (previous!=null) {
            logger.warn(String.format("SAML message replaced, it already exists with ID:%s for subdomain:%s.", messageId, IdentityZoneHolder.get().getSubdomain()));
        }
    }

    @Override
    public XMLObject retrieveMessage(String messageId) {
        XMLObject result = messages.remove(messageId);
        logger.debug(String.format("%s - Retrieving SAML message with ID:%s for subdomain:%s",
                                   result==null ? "Failure" : "Success",
                                   messageId,
                                   IdentityZoneHolder.get().getSubdomain())
        );
        return result;
    }
}
