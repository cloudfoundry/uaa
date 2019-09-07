/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;

import java.util.List;

@Deprecated
/**
 * Use {@link JsonWebKeySet}
 */
public class VerificationKeysListResponse extends JsonWebKeySet<VerificationKeyResponse> {
    public VerificationKeysListResponse(List<VerificationKeyResponse> keys) {
        super(keys);
    }
}
