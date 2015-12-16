package org.cloudfoundry.identity.uaa.account;

public class ConflictException extends RuntimeException {
    String userId;

    public ConflictException(String userId) {
        super(userId + " is not part of the UAA origin");
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }
}
