package org.cloudfoundry.identity.uaa.mock.limited;

import org.cloudfoundry.identity.uaa.mock.token.JwtBearerGrantMockMvcTests;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import java.io.File;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.resetLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.setLimitedModeStatusFile;

public class LimitedModeJwtBearerGrantMockMvcTests extends JwtBearerGrantMockMvcTests {
    private File existingStatusFile;

    @BeforeEach
    public void setUpLimitedModeContext(
            @Autowired @Qualifier("defaultUserAuthorities") Object defaultAuthorities
    ) throws Exception {
        super.setUpContext(defaultAuthorities);
        existingStatusFile = getLimitedModeStatusFile(webApplicationContext);
        setLimitedModeStatusFile(webApplicationContext);
    }

    @AfterEach
    public void tearDown() {
        resetLimitedModeStatusFile(webApplicationContext, existingStatusFile);
    }
}
