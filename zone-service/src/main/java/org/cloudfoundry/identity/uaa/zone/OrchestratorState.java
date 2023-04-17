package org.cloudfoundry.identity.uaa.zone;

public enum OrchestratorState {
    FOUND("FOUND"),
    NOT_FOUND("NOT_FOUND"),
    CREATE_IN_PROGRESS("CREATE_IN_PROGRESS"),
    PERMANENT_FAILURE("PERMANENT_FAILURE"),
    SERVER_FAILURE("SERVER_FAILURE");

    private final String value;

    OrchestratorState(String state) {
        this.value = state;
    }

    @Override
    public String toString() {
        return value;
    }
}
