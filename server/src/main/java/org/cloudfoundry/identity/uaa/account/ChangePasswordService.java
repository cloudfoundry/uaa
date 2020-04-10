
package org.cloudfoundry.identity.uaa.account;

public interface ChangePasswordService {
    void changePassword(String username, String currentPassword, String newPassword);
}
