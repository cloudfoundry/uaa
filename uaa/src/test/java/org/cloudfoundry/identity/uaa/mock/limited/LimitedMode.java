package org.cloudfoundry.identity.uaa.mock.limited;

import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.ActiveProfiles;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter.DEGRADED;

/**
 * Created by taitz.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(LimitedModeExtension.class)
@ActiveProfiles(DEGRADED)
@interface LimitedMode {
}
