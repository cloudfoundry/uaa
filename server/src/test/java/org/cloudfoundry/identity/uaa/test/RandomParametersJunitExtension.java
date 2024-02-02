package org.cloudfoundry.identity.uaa.test;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Parameter;

public class RandomParametersJunitExtension implements ParameterResolver {
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.PARAMETER)
    public @interface RandomValue {
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        return parameterContext.isAnnotated(RandomValue.class);
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        return getRandomValue(parameterContext.getParameter(), extensionContext);
    }

    private Object getRandomValue(Parameter parameter, ExtensionContext extensionContext) {
        Class<?> type = parameter.getType();
        java.util.Random random = extensionContext.getRoot().getStore(ExtensionContext.Namespace.GLOBAL)//
                .getOrComputeIfAbsent(java.util.Random.class);
        if (int.class.equals(type)) {
            return random.nextInt();
        }
        if (double.class.equals(type)) {
            return random.nextDouble();
        }
        if (String.class.equals(type)) {
            return RandomStringUtils.randomAlphabetic(10);
        }
        throw new ParameterResolutionException("No random generator implemented for " + type);
    }
}
