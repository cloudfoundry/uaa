package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

@WithDatabaseContext
class InMemoryExpiringCodeStoreTest extends ExpiringCodeStoreTests {

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        super.expiringCodeStore = new InMemoryExpiringCodeStore(super.mockTimeService);
    }

    @Override
    int countCodes() {
        Map map = (Map) ReflectionTestUtils.getField(expiringCodeStore, "store");
        return map.size();
    }
}