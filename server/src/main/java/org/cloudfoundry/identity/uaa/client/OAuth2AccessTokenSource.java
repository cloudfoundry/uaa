/*
 * *****************************************************************************
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
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestOperations;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2AccessTokenSource implements InitializingBean, PreAuthenticatedPrincipalSource<String> {

    private OAuth2RestOperations restTemplate;

    /**
     * A rest template to be used to contact the remote user info endpoint.
     * Normally an instance of {@link OAuth2RestTemplate}.
     * 
     * @param restTemplate a rest template
     */
    public void setRestTemplate(OAuth2RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.state(restTemplate != null, "RestTemplate URL must be provided");
    }

    @Override
    public String getPrincipal() {
        return restTemplate.getAccessToken().getValue();
    }

}
