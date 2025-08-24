package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.services.ScimUserService;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import jakarta.validation.constraints.NotNull;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.isEmpty;
import static org.springframework.util.StringUtils.hasText;

/**
 * Convenience class for provisioning user accounts from {@link UaaUser}
 * instances.
 */
public class ScimUserBootstrap implements
        InitializingBean,
        ApplicationListener<ApplicationEvent>,
        ApplicationEventPublisherAware {

    private static final Logger logger = LoggerFactory.getLogger(ScimUserBootstrap.class);

    private final ScimUserProvisioning scimUserProvisioning;
    private final ScimUserService scimUserService;
    private final ScimGroupProvisioning scimGroupProvisioning;
    private final ScimGroupMembershipManager membershipManager;
    private final IdentityZoneManager identityZoneManager;
    private final Collection<UaaUser> users;
    private final boolean override;
    private final List<String> usersToDelete;
    private final boolean aliasEntitiesEnabled;
    private ApplicationEventPublisher publisher;

    /**
     *
     * @param users Users to create
     * @param override Flag to indicate that user accounts can be updated as well as created
     */
    public ScimUserBootstrap(
            final ScimUserProvisioning scimUserProvisioning,
            final ScimUserService scimUserService,
            final ScimGroupProvisioning scimGroupProvisioning,
            final ScimGroupMembershipManager membershipManager,
            final IdentityZoneManager identityZoneManager,
            final Collection<UaaUser> users,
            final boolean override,
            final List<String> usersToDelete,
            final boolean aliasEntitiesEnabled
    ) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.scimUserService = scimUserService;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.membershipManager = membershipManager;
        this.identityZoneManager = identityZoneManager;
        this.users = Collections.unmodifiableCollection(users);
        this.override = override;
        this.usersToDelete = usersToDelete;
        this.aliasEntitiesEnabled = aliasEntitiesEnabled;
    }

    @Override
    public void afterPropertiesSet() {
        List<UaaUser> users = new LinkedList<>(ofNullable(this.users).orElse(emptyList()));
        List<String> deleteMe = ofNullable(usersToDelete).orElse(emptyList());
        users.removeIf(u -> deleteMe.contains(u.getUsername()));
        for (UaaUser u : users) {
            u.setVerified(true);
            addUser(u);
        }
    }

    private void deleteUsers(@NotNull List<String> deleteList) {
        if (deleteList.isEmpty()) {
            return;
        }
        StringBuilder filter = new StringBuilder();
        for (int i = deleteList.size() - 1; i >= 0; i--) {
            filter.append("username eq \"");
            filter.append(deleteList.get(i));
            filter.append("\"");
            if (i > 0) {
                filter.append(" or ");
            }
        }
        List<ScimUser> list = scimUserProvisioning.query("origin eq \"uaa\" and (" + filter.toString() + ")", identityZoneManager.getCurrentIdentityZoneId());
        for (ScimUser delete : list) {
            publish(new EntityDeletedEvent<>(delete, SystemAuthentication.SYSTEM_AUTHENTICATION, identityZoneManager.getCurrentIdentityZoneId()));
        }
    }

    private ScimUser getScimUser(UaaUser user) {
        List<ScimUser> users = scimUserProvisioning.query("userName eq \"" + user.getUsername() + "\"" +
                " and origin eq \"" +
                (user.getOrigin() == null ? OriginKeys.UAA : user.getOrigin()) + "\"", identityZoneManager.getCurrentIdentityZoneId());

        if (users.isEmpty() && StringUtils.hasText(user.getId())) {
            try {
                users = Collections.singletonList(scimUserProvisioning.retrieve(user.getId(), identityZoneManager.getCurrentIdentityZoneId()));
            } catch (ScimResourceNotFoundException x) {
                logger.debug("Unable to find scim user based on ID:{}", user.getId());
            }
        }
        return users.isEmpty() ? null : users.getFirst();
    }

    /**
     * Add a user account from the properties provided.
     *
     * @param user a UaaUser
     */
    private void addUser(UaaUser user) {
        ScimUser scimUser = getScimUser(user);
        if (scimUser == null) {
            if (isEmpty(user.getPassword()) && user.getOrigin().equals(OriginKeys.UAA)) {
                logger.debug("User's password cannot be empty");
                throw new InvalidPasswordException("Password cannot be empty", BAD_REQUEST);
            }
            createNewUser(user);
        } else {
            if (override) {
                updateUser(scimUser, user);
            } else {
                logger.debug("Override flag not set. Not registering existing user: {}", user);
            }
        }
    }

    private void updateUser(ScimUser existingUser, UaaUser updatedUser) {
        updateUser(existingUser, updatedUser, true);
    }

    private void updateUser(ScimUser existingUser, UaaUser updatedUser, boolean updateGroups) {
        String id = existingUser.getId();
        logger.debug("Updating user account: {} with SCIM Id: {}", updatedUser, id);
        if (updateGroups) {
            logger.debug("Removing existing group memberships ...");
            Set<ScimGroup> existingGroups = membershipManager.getGroupsWithMember(id, true, identityZoneManager.getCurrentIdentityZoneId());

            for (ScimGroup g : existingGroups) {
                removeFromGroup(id, g.getDisplayName());
            }
        }

        final ScimUser newScimUser = convertToScimUser(updatedUser);
        newScimUser.setVersion(existingUser.getVersion());
        newScimUser.setZoneId(existingUser.getZoneId());

        /* the user in the event won't have the alias properties set, we must therefore propagate them from the existing
         * user, if present */
        if (hasText(existingUser.getAliasId()) && hasText(existingUser.getAliasZid())) {
            newScimUser.setAliasId(existingUser.getAliasId());
            newScimUser.setAliasZid(existingUser.getAliasZid());
        }

        if (aliasEntitiesEnabled) {
            // update the user and propagate the changes to the alias, if present
            scimUserService.updateUser(id, newScimUser);
        } else {
            // update only the original user, even if it has an alias (the alias properties remain unchanged)
            scimUserProvisioning.update(id, newScimUser, identityZoneManager.getCurrentIdentityZoneId());
        }

        if (OriginKeys.UAA.equals(newScimUser.getOrigin()) && hasText(updatedUser.getPassword())) { //password is not relevant for non UAA users
            scimUserProvisioning.changePassword(id, null, updatedUser.getPassword(), identityZoneManager.getCurrentIdentityZoneId());
        }
        if (updateGroups) {
            Collection<String> newGroups = convertToGroups(updatedUser.getAuthorities());
            logger.debug("Adding new groups {}", newGroups);
            addGroups(id, newGroups, newScimUser.getOrigin());
        }
    }

    private void createNewUser(UaaUser user) {
        logger.debug("Registering new user account: {}", user);
        ScimUser newScimUser = scimUserProvisioning.createUser(convertToScimUser(user), user.getPassword(), identityZoneManager.getCurrentIdentityZoneId());
        addGroups(newScimUser.getId(), convertToGroups(user.getAuthorities()), newScimUser.getOrigin());
    }

    private void addGroups(String scimUserid, Collection<String> groups, String origin) {
        for (String group : groups) {
            addToGroup(scimUserid, group, origin, true);
        }
    }

    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof AuthEvent authEvent) {
            onApplicationEvent(authEvent);
        } else if (event instanceof ContextRefreshedEvent) {
            List<String> deleteMe = ofNullable(usersToDelete).orElse(emptyList());
            try {
                //we do delete users here, because only now are all components started
                //and ready to receive events
                deleteUsers(deleteMe);
            } catch (Exception e) {
                logger.warn("Unable to delete users from manifest.", e);
                throw new RuntimeException(e);
            }
        }
    }

    public void onApplicationEvent(AuthEvent event) {
        UaaUser uaaUser = event.getUser();
        if (event instanceof InvitedUserAuthenticatedEvent) {
            ScimUser user = getScimUser(uaaUser);
            // external users should default to not being verified
            if (!OriginKeys.UAA.equals(uaaUser.getOrigin())) {
                uaaUser.setVerified(false);
            }
            if (user != null) {
                updateUser(user, uaaUser, false);
            }
            return;
        }
        if (event instanceof ExternalGroupAuthorizationEvent exEvent) {
            //delete previous membership relation ships
            String origin = exEvent.getUser().getOrigin();
            if (!OriginKeys.UAA.equals(origin)) {
                Set<ScimGroup> groupsWithMember = membershipManager.getGroupsWithExternalMember(exEvent.getUser().getId(), origin, identityZoneManager.getCurrentIdentityZoneId());
                Map<String, ScimGroup> groupsMap = groupsWithMember.stream().collect(Collectors.toMap(ScimGroup::getDisplayName, Function.identity()));
                Collection<? extends GrantedAuthority> externalAuthorities = new LinkedHashSet<>(exEvent.getExternalAuthorities());
                for (GrantedAuthority authority : externalAuthorities) {
                    if (groupsMap.containsKey(authority.getAuthority())) {
                        groupsMap.remove(authority.getAuthority());
                    } else {
                        addToGroup(exEvent.getUser().getId(), authority.getAuthority(), origin, exEvent.isAddGroups());
                    }
                }
                for (ScimGroup group : groupsMap.values()) {
                    try {
                        membershipManager.removeMemberById(group.getId(), exEvent.getUser().getId(), group.getZoneId());
                    } catch (MemberNotFoundException ex) {
                        // do nothing
                    }
                }
            }
            //update the user itself
            if (event.isUserModified()) {
                //update the user itself
                ScimUser user = getScimUser(uaaUser);
                if (user != null) {
                    updateUser(user, uaaUser, false);
                }
            }
            return;
        }

        if (event instanceof NewUserAuthenticatedEvent) {
            addUser(uaaUser);
        }
    }

    private void addToGroup(String scimUserId, String gName, String origin, boolean addGroup) {
        if (!StringUtils.hasText(gName)) {
            return;
        }
        logger.debug("Adding to group: {}", gName);
        ScimGroup group;
        try {
            group = getOrCreateGroup(gName, addGroup);
        }
        catch (ScimResourceAlreadyExistsException e) {
            logger.debug("Unexpected ScimResourceAlreadyExistsException: {}. Retrying...", e.getMessage());
            group = getOrCreateGroup(gName, addGroup);
        }

        if (group == null) {
            return;
        }

        try {
            ScimGroupMember groupMember = new ScimGroupMember(scimUserId);
            groupMember.setOrigin(ofNullable(origin).orElse(OriginKeys.UAA));
            membershipManager.addMember(group.getId(), groupMember, identityZoneManager.getCurrentIdentityZoneId());
        } catch (MemberAlreadyExistsException | DuplicateKeyException ex) {
            // do nothing
        }
    }

    private ScimGroup getOrCreateGroup(String gName, boolean addGroup) {
        ScimGroup group = null;
        try {
            group = scimGroupProvisioning.getByName(gName, identityZoneManager.getCurrentIdentityZoneId());
        }
        catch (IncorrectResultSizeDataAccessException e) {
            if (!addGroup) {
                logger.debug("No group found with name:{}. Group membership will not be added.", gName);
                return null;
            } else {
                group = new ScimGroup(null, gName, identityZoneManager.getCurrentIdentityZoneId());
                try {
                    group = scimGroupProvisioning.create(group, identityZoneManager.getCurrentIdentityZoneId());
                }
                catch (ScimResourceAlreadyExistsException sraee) {
                    logger.debug("Unexpected ScimResourceAlreadyExistsException: {}. Retrying...", sraee.getMessage());
                    group = scimGroupProvisioning.create(group, identityZoneManager.getCurrentIdentityZoneId());
                }
            }
        }

        return group;
    }

    private void removeFromGroup(String scimUserId, String gName) {
        if (!StringUtils.hasText(gName)) {
            return;
        }
        logger.debug("Removing membership of group: {}", gName);
        List<ScimGroup> g = scimGroupProvisioning.query("displayName eq \"%s\"".formatted(gName), identityZoneManager.getCurrentIdentityZoneId());
        ScimGroup group;
        if (g == null || g.isEmpty()) {
            return;
        } else {
            group = g.getFirst();
        }
        try {
            membershipManager.removeMemberById(group.getId(), scimUserId, identityZoneManager.getCurrentIdentityZoneId());
        } catch (MemberNotFoundException ex) {
            // do nothing
        }
    }

    /**
     * Convert UaaUser to SCIM data.
     */
    private ScimUser convertToScimUser(UaaUser user) {
        ScimUser scim = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
        scim.addPhoneNumber(user.getPhoneNumber());
        scim.addEmail(user.getEmail());
        scim.setOrigin(user.getOrigin());
        scim.setExternalId(user.getExternalId());
        scim.setVerified(user.isVerified());
        return scim;
    }

    /**
     * Convert authorities to group names.
     */
    private Collection<String> convertToGroups(List<? extends GrantedAuthority> authorities) {
        List<String> groups = new ArrayList<>();
        for (GrantedAuthority authority : authorities) {
            groups.add(authority.getAuthority());
        }
        return groups;
    }

    public void publish(ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        publisher = applicationEventPublisher;
    }
}
