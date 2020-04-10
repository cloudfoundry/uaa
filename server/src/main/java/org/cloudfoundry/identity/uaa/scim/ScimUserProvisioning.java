package org.cloudfoundry.identity.uaa.scim;

import java.util.List;
import org.cloudfoundry.identity.uaa.resources.Queryable;
import org.cloudfoundry.identity.uaa.resources.ResourceManager;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

public interface ScimUserProvisioning extends ResourceManager<ScimUser>, Queryable<ScimUser> {

  ScimUser createUser(ScimUser user, String password, String zoneId)
      throws InvalidPasswordException, InvalidScimResourceException;

  List<ScimUser> retrieveByEmailAndZone(String email, String origin, String zoneId);

  List<ScimUser> retrieveByUsernameAndZone(String username, String zoneId);

  List<ScimUser> retrieveByUsernameAndOriginAndZone(String username, String origin, String zoneId);

  void changePassword(String id, String oldPassword, String newPassword, String zoneId)
      throws ScimResourceNotFoundException;

  void updatePasswordChangeRequired(String userId, boolean passwordChangeRequired, String zoneId)
      throws ScimResourceNotFoundException;

  ScimUser verifyUser(String id, int version, String zoneId)
      throws ScimResourceNotFoundException, InvalidScimResourceException;

  boolean checkPasswordMatches(String id, String password, String zoneId)
      throws ScimResourceNotFoundException;

  boolean checkPasswordChangeIndividuallyRequired(String id, String zoneId)
      throws ScimResourceNotFoundException;

  void updateLastLogonTime(String id, String zoneId);
}
