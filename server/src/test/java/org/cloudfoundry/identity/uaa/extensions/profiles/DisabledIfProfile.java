package org.cloudfoundry.identity.uaa.extensions.profiles;

import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Disable the test if any of the given profiles are present in the TestContext.
 * <p>
 * Annotate test methods or test classes. In case there are nested annotations, e.g.
 * one on the method and one on the class, the closest annotation is taken into account.
 * <p>
 * When the {@link EnabledIfProfile} element is present, this annotation takes precedence.
 * <p>
 * Usage:
 *
 * <pre>
 * &#64;ExtendWith(SpringExtension.class)
 * &#64;ContextConfiguration(...)
 * // ...
 * class MyAppTests {
 *      &#64;Test
 *      void runsEveryTime() {
 *          // ...
 *      }
 *
 *      &#64;Test
 *      &#64;DisabledIfProfile({"postgresql", "mysql"})
 *      void doNotRunForRealDb() {
 *          // Does not run when the active profiles contain "postgresql" or "mysql"
 *      }
 * }
 * </pre>
 *
 * @see ProfileSelectionExtension
 * @see EnabledIfProfile
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(ProfileSelectionExtension.class)
public @interface DisabledIfProfile {

    String[] value() default {};
}
