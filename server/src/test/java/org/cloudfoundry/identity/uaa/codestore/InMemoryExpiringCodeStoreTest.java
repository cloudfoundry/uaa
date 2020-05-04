package org.cloudfoundry.identity.uaa.codestore;

import org.junit.Before;

public class InMemoryExpiringCodeStoreTest extends ExpiringCodeStoreTests {

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        super.expiringCodeStore = new InMemoryExpiringCodeStore(super.mockTimeService);
    }
}