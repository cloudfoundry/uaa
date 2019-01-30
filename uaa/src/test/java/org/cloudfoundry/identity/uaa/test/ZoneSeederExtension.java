package org.cloudfoundry.identity.uaa.test;

import org.junit.jupiter.api.extension.*;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.ArrayList;
import java.util.List;

public class ZoneSeederExtension implements AfterEachCallback, ParameterResolver {

    private List<ZoneSeeder> zoneSeeders = new ArrayList<>();

    @Override
    public void afterEach(ExtensionContext extensionContext) {
        for (ZoneSeeder zoneSeeder : zoneSeeders) {
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
        ApplicationContext applicationContext = SpringExtension.getApplicationContext(extensionContext);
        ZoneSeeder zoneSeeder = new ZoneSeeder(applicationContext);
        zoneSeeders.add(zoneSeeder);
        return zoneSeeder;
    }

}
