package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.ConfigurableWebApplicationContext;

public class YamlServletProfileInitializerContextInitializer {

    public void initializeContext(ConfigurableWebApplicationContext context, String yamlPath) {
        MockServletContext servletContext = new MockServletContext();
        MockServletConfig servletConfig = new MockServletConfig(servletContext);
        servletConfig.addInitParameter("environmentConfigDefaults", yamlPath);
        context.setServletContext(servletContext);
        context.setServletConfig(servletConfig);
        new YamlServletProfileInitializer().initialize(context);
    }
}
