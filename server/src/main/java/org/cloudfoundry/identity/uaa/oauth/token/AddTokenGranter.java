/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

/**
 * This class just adds custom token granters to the
 * {@link CompositeTokenGranter} object that is created by the
 * <pre>&lt;oauth:authorization-server&gt;</pre> element
 */
public class AddTokenGranter {


    private final TokenGranter userTokenGranter;
    private final TokenGranter compositeTokenGranter;

    public AddTokenGranter(TokenGranter userTokenGranter, TokenGranter compositeTokenGranter) {
        this.userTokenGranter = userTokenGranter;
        this.compositeTokenGranter = compositeTokenGranter;
        if (compositeTokenGranter == null) {
            throw new NullPointerException("Expected non null "+CompositeTokenGranter.class.getName());
        } else if (compositeTokenGranter instanceof CompositeTokenGranter) {
            CompositeTokenGranter cg = (CompositeTokenGranter)compositeTokenGranter;
            cg.addTokenGranter(userTokenGranter);
        } else {
            throw new IllegalArgumentException(
                "Expected "+CompositeTokenGranter.class.getName()+
                " but received "+
                compositeTokenGranter.getClass().getName()
            );
        }
    }

}
