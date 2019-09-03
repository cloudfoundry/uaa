package org.cloudfoundry.identity.uaa.test;

import org.junit.jupiter.api.extension.*;
import org.springframework.restdocs.ManualRestDocumentation;

public class JUnitRestDocumentationExtension implements BeforeEachCallback, AfterEachCallback, ParameterResolver {
    ManualRestDocumentation restDocumentation = new ManualRestDocumentation(System.getProperty("docs.build.generated.snippets.dir"));

    @Override
    public void beforeEach(ExtensionContext context) {
        restDocumentation.beforeTest(context.getTestClass().get(), context.getTestMethod().get().getName());
    }

    @Override
    public void afterEach(ExtensionContext context) {
        restDocumentation.afterTest();
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return parameterContext.getParameter().getType() == ManualRestDocumentation.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return restDocumentation;
    }
}
