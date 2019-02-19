package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = {
        SpringServletAndHoneycombTestConfig.class,
        TestClientAndMockMvcTestConfig.class
})
public @interface DefaultTestContext {
}
