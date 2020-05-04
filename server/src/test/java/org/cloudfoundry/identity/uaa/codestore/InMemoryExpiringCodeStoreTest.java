package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.BeforeEach;

@WithDatabaseContext
class InMemoryExpiringCodeStoreTest extends ExpiringCodeStoreTests {

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        super.expiringCodeStore = new InMemoryExpiringCodeStore(super.mockTimeService);
    }
}