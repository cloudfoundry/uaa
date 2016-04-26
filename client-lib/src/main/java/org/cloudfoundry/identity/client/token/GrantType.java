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

package org.cloudfoundry.identity.client.token;

/**
 * Represent the standard Oauth 2 grant types
 */
public enum GrantType {
    CLIENT_CREDENTIALS,
    PASSWORD,
    PASSWORD_WITH_PASSCODE,
    IMPLICIT,
    AUTHORIZATION_CODE,
    AUTHORIZATION_CODE_WITH_TOKEN,
    REFRESH_TOKEN,
    FETCH_TOKEN_FROM_CODE
}
