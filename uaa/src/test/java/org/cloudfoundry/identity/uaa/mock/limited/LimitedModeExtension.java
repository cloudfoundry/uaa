package org.cloudfoundry.identity.uaa.mock.limited;

import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import static org.junit.Assert.assertTrue;
import static org.springframework.test.context.junit.jupiter.SpringExtension.getApplicationContext;

/**
 * Created by taitz.
 */
class LimitedModeExtension implements BeforeEachCallback {

    @Override
    public void beforeEach(ExtensionContext context) {
        LimitedModeUaaFilter limitedModeUaaFilter = getApplicationContext(context).getBean(LimitedModeUaaFilter.class);
        assertTrue(limitedModeUaaFilter.isEnabled()); 
    }

}
