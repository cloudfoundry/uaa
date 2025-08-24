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

package org.cloudfoundry.identity.uaa.impl.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.util.Assert;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.error.YAMLException;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Arrays;
import java.util.Set;

/**
 * Uses a defined SnakeYAML constructor to validate the raw YAML obtained from
 * the environment.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class YamlConfigurationValidator<T> implements FactoryBean<T>, InitializingBean, EnvironmentAware {

    private static final Logger logger = LoggerFactory.getLogger(YamlConfigurationValidator.class);

    private final Constructor constructor;

    private boolean exceptionIfInvalid;

    private String yaml;

    private T configuration;

    /**
     * Sets a validation constructor which will be applied to the YAML doc to
     * see whether it matches the expected
     * Javabean.
     *
     * @param constructor the validation constructor, must not be {@literal null}
     */
    public YamlConfigurationValidator(Constructor constructor) {
        Assert.notNull(constructor, "must not be null");
        this.constructor = constructor;
    }

    /**
     * @param yaml the yaml to set
     */
    public void setYaml(String yaml) {
        this.yaml = yaml;
    }

    public void setExceptionIfInvalid(boolean exceptionIfInvalid) {
        this.exceptionIfInvalid = exceptionIfInvalid;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void afterPropertiesSet() {

        Assert.state(yaml != null, "Yaml document should not be null");

        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

        try {
            logger.trace("Yaml document is\n{}", yaml);
            configuration = (T) (new Yaml(constructor)).load(yaml);
            Set<ConstraintViolation<T>> errors = validator.validate(configuration);

            if (!errors.isEmpty()) {
                logger.error("YAML configuration failed validation");
                for (ConstraintViolation<?> error : errors) {
                    logger.error("{}: {}", error.getPropertyPath(), error.getMessage());
                }
                if (exceptionIfInvalid) {
                    @SuppressWarnings("rawtypes")
                    ConstraintViolationException summary = new ConstraintViolationException(errors);
                    throw summary;
                }
            }
        } catch (YAMLException e) {
            if (exceptionIfInvalid) {
                throw e;
            }
        }
    }

    @Override
    public Class<?> getObjectType() {
        if (configuration == null) {
            return Object.class;
        }
        return configuration.getClass();
    }

    @Override
    public boolean isSingleton() {
        return true;
    }

    @Override
    public T getObject() {
        if (configuration == null) {
            afterPropertiesSet();
        }
        return configuration;
    }

    @Override
    public void setEnvironment(Environment environment) {
        if (Arrays.asList(environment.getActiveProfiles()).contains("strict")) {
            this.exceptionIfInvalid = true;
        }

    }

}
