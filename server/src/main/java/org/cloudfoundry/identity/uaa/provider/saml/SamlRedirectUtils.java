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

package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.web.util.UriComponentsBuilder;

public class SamlRedirectUtils {

    public static String getIdpRedirectUrl(SamlIdentityProviderDefinition definition, String entityId) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromPath("saml/discovery");
        builder.queryParam("returnIDParam", "idp");
        builder.queryParam("entityID", getZonifiedEntityId(entityId));
        builder.queryParam("idp", definition.getIdpEntityAlias());
        builder.queryParam("isPassive", "true");
        return builder.build().toUriString();
    }

    public static String getZonifiedEntityId(String entityID) {
        if (UaaUrlUtils.isUrl(entityID)) {
            return UaaUrlUtils.addSubdomainToUrl(entityID);
        } else {
            return UaaUrlUtils.getSubdomain()+entityID;
        }
    }

}
