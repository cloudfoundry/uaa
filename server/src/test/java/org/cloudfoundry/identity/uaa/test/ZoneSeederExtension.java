package org.cloudfoundry.identity.uaa.test;

import org.junit.jupiter.api.extension.*;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.*;

public class ZoneSeederExtension implements AfterEachCallback, ParameterResolver, BeforeTestExecutionCallback {

    private final Map<Object, ZoneSeeder> zoneSeeders = new HashMap<>();

    @Override
    public void afterEach(ExtensionContext extensionContext) {
        for (ZoneSeeder zoneSeeder : zoneSeeders.values()) {
            zoneSeeder.destroy();
        }
        zoneSeeders.clear();
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return parameterContext.getParameter().getType() == ZoneSeeder.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        Object testInstance = extensionContext.getTestInstance().get();
        ApplicationContext applicationContext = SpringExtension.getApplicationContext(extensionContext);
        ZoneSeeder zoneSeeder = new ZoneSeeder(applicationContext);
        zoneSeeders.put(testInstance, zoneSeeder);
        return zoneSeeder;
    }

    @Override
    public void beforeTestExecution(ExtensionContext extensionContext) throws Exception {
        Object testInstance = extensionContext.getTestInstance().get();
        ZoneSeeder zoneSeeder = zoneSeeders.get(testInstance);
        if (zoneSeeder != null) {
            zoneSeeder.seed();
        }
    }
}
