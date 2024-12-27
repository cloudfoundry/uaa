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
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SamlRedirectUtilsTest {
    private static final String ENTITY_ID = "entityId";
    private static final String ZONE_ID = "zone-id";

    @Test
    void getIdpRedirectUrl() {
        SamlIdentityProviderDefinition definition =
                new SamlIdentityProviderDefinition()
                        .setMetaDataLocation("http://some.meta.data")
                        .setIdpEntityAlias("simplesamlphp-url")
                        .setNameID("nameID")
                        .setMetadataTrustCheck(true)
                        .setLinkText("link text")
                        .setZoneId(IdentityZone.getUaaZoneId());

        String url = SamlRedirectUtils.getIdpRedirectUrl(definition);
        assertThat(url).isEqualTo("saml2/authenticate/simplesamlphp-url");
    }

    @Test
    void getZonifiedEntityId() {
        assertThat(SamlRedirectUtils.getZonifiedEntityId(ENTITY_ID, IdentityZone.getUaa())).isEqualTo(ENTITY_ID);
    }

    @Test
    void getZonifiedEntityId_forOtherZone() {
        IdentityZone otherZone = new IdentityZone();
        otherZone.setId(ZONE_ID);
        otherZone.setSubdomain(ZONE_ID);

        assertThat(SamlRedirectUtils.getZonifiedEntityId(ENTITY_ID, otherZone)).isEqualTo("zone-id.entityId");
    }

    @Test
    void zonifiedValidAndInvalidEntityID() {
        IdentityZone newZone = new IdentityZone();
        newZone.setId("new-zone-id");
        newZone.setName("new-zone-id");
        newZone.setSubdomain("new-zone-id");
        newZone.getConfig().getSamlConfig().setEntityID("local-name");

        // valid entityID from SamlConfig
        assertThat(SamlRedirectUtils.getZonifiedEntityId("local-name", newZone))
                .isEqualTo("local-name");

        // remove SamlConfig
        newZone.getConfig().setSamlConfig(null);
        assertThat(SamlRedirectUtils.getZonifiedEntityId("local-idp", newZone)).isNotNull();
        // now the entityID is generated id as before this change
        assertThat(SamlRedirectUtils.getZonifiedEntityId("local-name", newZone)).isEqualTo("new-zone-id.local-name");
    }
}
