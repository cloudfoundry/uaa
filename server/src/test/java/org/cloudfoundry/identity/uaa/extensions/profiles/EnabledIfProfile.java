package org.cloudfoundry.identity.uaa.extensions.profiles;

import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Enable the test only when any of the given profiles are present in the TestContext.
 * <p>
 * Annotate test methods or test classes. In case there are nested annotations, e.g.
 * one on the method and one on the class, the closest annotation is taken into account.
 * <p>
 * When the {@link DisabledIfProfile} annotation is also present, {@link DisabledIfProfile}
 * takes precedence.
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
 *      &#64;EnabledIfProfile({"postgresql", "mysql"})
 *      void onlyRunForRealDb() {
 *          // Only runs when the active profiles contain "postgresql" or "mysql"
 *      }
 * }
 * </pre>
 *
 * @see ProfileSelectionExtension
 * @see DisabledIfProfile
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(ProfileSelectionExtension.class)
public @interface EnabledIfProfile {

    String[] value() default {};
}
