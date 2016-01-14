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

package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Assert;
import org.junit.Test;

public class SamlRedirectUtilsTest {

    @Test
    public void testGetIdpRedirectUrl() throws Exception {
        SamlIdentityProviderDefinition definition =
            new SamlIdentityProviderDefinition()
                .setMetaDataLocation("http://some.meta.data")
                .setIdpEntityAlias("simplesamlphp-url")
                .setNameID("nameID")
                .setMetadataTrustCheck(true)
                .setLinkText("link text")
                .setZoneId(IdentityZone.getUaa().getId());

        String url = SamlRedirectUtils.getIdpRedirectUrl(definition, "login.identity.cf-app.com");
        Assert.assertEquals("saml/discovery?returnIDParam=idp&entityID=login.identity.cf-app.com&idp=simplesamlphp-url&isPassive=true", url);
    }
}
