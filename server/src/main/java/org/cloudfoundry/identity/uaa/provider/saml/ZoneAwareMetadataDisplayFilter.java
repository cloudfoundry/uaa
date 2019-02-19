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

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.io.MarshallingException;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class ZoneAwareMetadataDisplayFilter extends MetadataDisplayFilter {

    protected final MetadataGenerator generator;

    public ZoneAwareMetadataDisplayFilter(MetadataGenerator generator) {
        this.generator = generator;
    }

    public MetadataGenerator getGenerator() {
        return generator;
    }

    @Override
    protected void processMetadataDisplay(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        super.processMetadataDisplay(request, response);
        response.setHeader("Content-Disposition", String.format("attachment; filename=\"saml-%ssp.xml\"",
                !IdentityZoneHolder.isUaa() ? IdentityZoneHolder.get().getSubdomain() + "-" : ""));
    }

    @Override
    protected void displayMetadata(String spEntityName, PrintWriter writer) throws ServletException {
        try {
            EntityDescriptor descriptor = getGenerator().generateMetadata();
            if (descriptor == null) {
                throw new ServletException("Metadata entity with ID " + manager.getHostedSPName() + " wasn't found");
            } else {
                writer.print(getMetadataAsString(descriptor));
            }
        } catch (MarshallingException e) {
            log.error("Error marshalling entity descriptor", e);
            throw new ServletException(e);
        } catch (Exception e) {
            log.error("Error retrieving metadata", e);
            throw new ServletException("Error retrieving metadata", e);
        }
    }
}
