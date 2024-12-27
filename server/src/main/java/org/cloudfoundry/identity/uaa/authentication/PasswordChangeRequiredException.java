/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication;


import org.cloudfoundry.identity.uaa.oauth.InteractionRequiredException;

public class PasswordChangeRequiredException extends InteractionRequiredException {

    private final UaaAuthentication authentication;

    public PasswordChangeRequiredException(UaaAuthentication authentication, String msg) {
        super(msg);
        this.authentication = authentication;
    }

    public UaaAuthentication getAuthentication() {
        return authentication;
    }
}
