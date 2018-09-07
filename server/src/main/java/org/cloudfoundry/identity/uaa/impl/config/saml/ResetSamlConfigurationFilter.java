/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.impl.config.saml;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import static java.util.Arrays.asList;

public class ResetSamlConfigurationFilter extends OncePerRequestFilter {

    private final SamlConfigurationRepository spRepository;
    private final SamlConfigurationRepository idpRepository;

    @Autowired
    public ResetSamlConfigurationFilter(
        @Qualifier("idpSamlConfigurationRepository") SamlConfigurationRepository idpRepository,
        @Qualifier("spSamlConfigurationRepository") SamlConfigurationRepository spRepository
    ) {
        this.spRepository= spRepository;
        this.idpRepository = idpRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        try {
            //clean config going on
            reset();
            filterChain.doFilter(request, response);
        } finally {
            //clean config going out
            reset();
        }
    }

    private void reset() {
        for (SamlConfigurationRepository repository : asList(idpRepository, spRepository)) {
            if (repository instanceof ThreadLocalSamlConfigurationRepository) {
                ((ThreadLocalSamlConfigurationRepository)repository).reset();
            }
        }
    }
}
