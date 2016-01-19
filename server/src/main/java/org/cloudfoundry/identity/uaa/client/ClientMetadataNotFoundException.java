package org.cloudfoundry.identity.uaa.client;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

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
@ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "Client metadata not found")
public class ClientMetadataNotFoundException extends ClientMetadataException {

    public ClientMetadataNotFoundException(String clientId) {
        super("No existing metadata found for client " + clientId, HttpStatus.NOT_FOUND);
    }

}
