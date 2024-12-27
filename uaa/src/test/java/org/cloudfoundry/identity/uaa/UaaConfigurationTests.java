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
package org.cloudfoundry.identity.uaa;

import static org.junit.Assert.assertTrue;

import javax.validation.ConstraintViolationException;

import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.YamlConfigurationValidator;
import org.junit.Test;

/**
 * @author Luke Taylor
 */
public class UaaConfigurationTests {

    private final YamlConfigurationValidator<UaaConfiguration> validator = new YamlConfigurationValidator<>(
            new UaaConfiguration.UaaConfigConstructor());

    private void createValidator(final String yaml) {
        validator.setExceptionIfInvalid(true);
        validator.setYaml(yaml);
        validator.afterPropertiesSet();
    }

    @Test
    public void validYamlIsOk() throws Exception {
        createValidator(
                """
                name: uaa
                issuer.uri: http://foo.com
                oauth:
                  clients:
                    cf:
                      id: cf
                      authorized-grant-types: implicit
                  user:
                    authorities:
                      - openid
                      - scim.me
                  openid:
                    fallbackToAuthcode: false""");
    }

    @Test
    public void validClientIsOk() throws Exception {
        createValidator(
                """
                oauth:
                  clients:
                    cf:
                      id: cf
                      autoapprove: true
                      authorized-grant-types: implicit
                """);
        assertTrue(validator.getObject().oauth.clients.containsKey("cf"));
    }

    @Test(expected = ConstraintViolationException.class)
    public void invalidIssuerUriCausesException() throws Exception {
        createValidator("name: uaa\nissuer.uri: notauri\n");
    }
}
