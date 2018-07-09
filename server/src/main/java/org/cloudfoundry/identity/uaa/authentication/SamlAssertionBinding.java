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

package org.cloudfoundry.identity.uaa.authentication;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;

public class SamlAssertionBinding {

    /**
     * Creates default implementation of the binding.
     */
    public SamlAssertionBinding() {

    }



    public boolean supports(HttpServletRequest transport) {
        return HttpMethod.POST.name().equalsIgnoreCase(transport.getMethod()) &&
            transport.getParameter("assertion") != null;
    }

    public String getBindingURI() {
        return "urn:oasis:names:tc:SAML:2.0:bindings:URI";
    }
}
