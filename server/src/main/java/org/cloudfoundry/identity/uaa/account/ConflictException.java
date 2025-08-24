package org.cloudfoundry.identity.uaa.account;

public class ConflictException extends RuntimeException {
    String userId;
    String email;

    public ConflictException(String userId, String email) {
        super(userId + " is not part of the UAA origin");
        this.userId = userId;
        this.email = email;
    }

    public String getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }
}
