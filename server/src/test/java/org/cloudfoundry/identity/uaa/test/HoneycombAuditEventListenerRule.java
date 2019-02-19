package org.cloudfoundry.identity.uaa.test;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

public class HoneycombAuditEventListenerRule implements TestRule {
    @Override
    public Statement apply(Statement base, Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                HoneycombAuditEventTestListener.testRunning = description.getDisplayName();

                base.evaluate();
            }
        };
    }
}
