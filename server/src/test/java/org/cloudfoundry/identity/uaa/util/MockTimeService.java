package org.cloudfoundry.identity.uaa.util;

public class MockTimeService implements TimeService {

    private volatile long time = System.currentTimeMillis();

    @Override
    public long getCurrentTimeMillis() {
        return time;
    }

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        this.time = time;
    }

    public long addAndGet(long delta) {
        time += delta;
        return time;
    }
}