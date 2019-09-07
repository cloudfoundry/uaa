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
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.springframework.web.util.UriComponentsBuilder;

public class SamlRedirectUtils {

    public static String getIdpRedirectUrl(SamlIdentityProviderDefinition definition, String entityId, IdentityZone identityZone) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromPath("saml/discovery");
        builder.queryParam("returnIDParam", "idp");
        builder.queryParam("entityID", getZonifiedEntityId(entityId, identityZone));
        builder.queryParam("idp", definition.getIdpEntityAlias());
        builder.queryParam("isPassive", "true");
        return builder.build().toUriString();
    }

    public static String getZonifiedEntityId(String entityID, IdentityZone identityZone) {
        try{
            if (!identityZone.isUaa()) {
                String url = identityZone.getConfig().getSamlConfig().getEntityID();
                if (url != null) {
                    return url;
                }
            }
        } catch (Exception ignored) {}

        if (UaaUrlUtils.isUrl(entityID)) {
            return UaaUrlUtils.addSubdomainToUrl(entityID, identityZone.getSubdomain());
        } else {
            return UaaUrlUtils.getSubdomain(identityZone.getSubdomain()) + entityID;
        }
    }

    public static Response wrapAssertionIntoResponse(Assertion assertion, String assertionIssuer) {
        Response response = new ResponseBuilder().buildObject();
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(assertionIssuer);
        response.setIssuer(issuer);
        response.setID("id-" + System.currentTimeMillis());
        Status stat = new StatusBuilder().buildObject();
        // Set the status code
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
        stat.setStatusCode(statCode);
        // Set the status Message
        StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
        statMesssage.setMessage(null);
        stat.setStatusMessage(statMesssage);
        response.setStatus(stat);
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(new DateTime());
        response.getAssertions().add(assertion);
        //XMLHelper.adoptElement(assertion.getDOM(), assertion.getDOM().getOwnerDocument());
        return response;
    }

}
