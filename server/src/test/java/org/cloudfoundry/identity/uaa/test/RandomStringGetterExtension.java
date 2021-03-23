package org.cloudfoundry.identity.uaa.test;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

public class RandomStringGetterExtension implements ParameterResolver {

    @Override
    public boolean supportsParameter(
            final ParameterContext parameterContext,
            final ExtensionContext extensionContext
    ) throws ParameterResolutionException {
        return parameterContext.getParameter().getType() == RandomStringGetter.class;
    }

    @Override
    public Object resolveParameter(
            final ParameterContext parameterContext,
            final ExtensionContext extensionContext
    ) throws ParameterResolutionException {
        String randomString = RandomStringUtils.randomAlphabetic(7);
        return (RandomStringGetter) () -> randomString;
    }
}