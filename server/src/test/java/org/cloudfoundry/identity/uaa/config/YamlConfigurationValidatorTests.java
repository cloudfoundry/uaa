/*******************************************************************************
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
package org.cloudfoundry.identity.uaa.config;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import javax.validation.ConstraintViolationException;
import javax.validation.constraints.NotNull;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.impl.config.CustomPropertyConstructor;
import org.cloudfoundry.identity.uaa.impl.config.YamlConfigurationValidator;
import org.junit.After;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.yaml.snakeyaml.error.YAMLException;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class YamlConfigurationValidatorTests {

    private YamlConfigurationValidator<Foo> validator;

    private Foo createFoo(final String yaml) throws Exception {
        validator = new YamlConfigurationValidator<Foo>(new FooConstructor());
        validator.setYaml(yaml);
        validator.setExceptionIfInvalid(true);
        validator.afterPropertiesSet();
        return validator.getObject();
    }

    @After
    public void resetLog() {
        ReflectionTestUtils.setField(YamlConfigurationValidator.class, "logger", LogFactory.getLog(YamlConfigurationValidator.class));
    }

    @Test
    public void validYamlLoadsWithNoErrors() throws Exception {
        Foo foo = createFoo("foo-name: blah\nbar: blah");
        assertEquals("blah", foo.bar);
    }

    @Test(expected = YAMLException.class)
    public void unknownPropertyCausesLoadFailure() throws Exception {
        createFoo("hi: hello\nname: foo\nbar: blah");
    }

    @Test
    public void invalid_yaml_no_log() throws Exception {
        Log log = spy(LogFactory.getLog(YamlConfigurationValidator.class));

        ReflectionTestUtils.setField(YamlConfigurationValidator.class, "logger", log);

        validator = new YamlConfigurationValidator<>(new FooConstructor());
        validator.setExceptionIfInvalid(false);
        validator.setYaml("hi: hello\nname: foo\nbar: blah");
        validator.afterPropertiesSet();
        validator.getObject();

        verify(log, never()).error(any());
        verify(log, never()).error(any(), any());
    }

    @Test(expected = ConstraintViolationException.class)
    public void missingPropertyCausesValidationError() throws Exception {
        createFoo("bar: blah");
    }

    private static class Foo {
        @NotNull
        public String name;
        public String bar;
    }

    private static class FooConstructor extends CustomPropertyConstructor {

        public FooConstructor() {
            super(Foo.class);
            addPropertyAlias("foo-name", Foo.class, "name");
        }
    }
}
