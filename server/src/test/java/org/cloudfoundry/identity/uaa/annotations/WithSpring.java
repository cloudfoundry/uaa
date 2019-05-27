package org.cloudfoundry.identity.uaa.annotations;

import org.cloudfoundry.identity.uaa.test.TestWebAppContext;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @Deprecated. Use {@link org.cloudfoundry.identity.uaa.DefaultTestContext} instead.
 * This is part of the uaa module, so move it to the server module if you need it
 */
@Deprecated
@ExtendWith(SpringExtension.class)
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = {
        TestWebAppContext.class
})
public @interface WithSpring {
}
