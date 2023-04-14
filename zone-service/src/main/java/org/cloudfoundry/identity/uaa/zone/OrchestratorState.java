package org.cloudfoundry.identity.uaa.zone;

public enum OrchestratorState {
    FOUND("FOUND"),
    NOT_FOUND("NOT_FOUND"),
    PERMANENT_FAILURE("PERMANENT_FAILURE");

    private String value;

    OrchestratorState(String state) {
        this.value = state;
    }

    @Override
    public String toString() {
        return value;
    }
}
