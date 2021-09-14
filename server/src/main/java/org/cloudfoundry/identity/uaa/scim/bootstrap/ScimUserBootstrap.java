package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.*;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import javax.validation.constraints.NotNull;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.util.StringUtils.isEmpty;

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
    private final ScimGroupProvisioning scimGroupProvisioning;
    private final ScimGroupMembershipManager membershipManager;
    private final Collection<UaaUser> users;
    private final boolean override;
    private final List<String> usersToDelete;
    private ApplicationEventPublisher publisher;

    /**
     *
     * @param users Users to create
     * @param override Flag to indicate that user accounts can be updated as well as created
     */
    public ScimUserBootstrap(final ScimUserProvisioning scimUserProvisioning,
                             final ScimGroupProvisioning scimGroupProvisioning,
                             final ScimGroupMembershipManager membershipManager,
                             final Collection<UaaUser> users,
                             @Value("${scim.user.override:false}") final boolean override,
                             @Value("${delete.users:#{null}}") final List<String> usersToDelete) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.membershipManager = membershipManager;
        this.users = Collections.unmodifiableCollection(users);
        this.override = override;
        this.usersToDelete = usersToDelete;
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
        if (deleteList.size() == 0) {
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
        List<ScimUser> list = scimUserProvisioning.query("origin eq \"uaa\" and (" + filter.toString() + ")", IdentityZoneHolder.get().getId());
        for (ScimUser delete : list) {
            publish(new EntityDeletedEvent<>(delete, SystemAuthentication.SYSTEM_AUTHENTICATION, IdentityZoneHolder.getCurrentZoneId()));
        }
    }

    private ScimUser getScimUser(UaaUser user) {
        List<ScimUser> users = scimUserProvisioning.query("userName eq \"" + user.getUsername() + "\"" +
                " and origin eq \"" +
                (user.getOrigin() == null ? OriginKeys.UAA : user.getOrigin()) + "\"", IdentityZoneHolder.get().getId());

        if (users.isEmpty() && StringUtils.hasText(user.getId())) {
            try {
                users = Collections.singletonList(scimUserProvisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId()));
            } catch (ScimResourceNotFoundException x) {
                logger.debug("Unable to find scim user based on ID:" + user.getId());
            }
        }
        return users.isEmpty() ? null : users.get(0);
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
                logger.debug("Override flag not set. Not registering existing user: " + user);
            }
        }
    }

    private void updateUser(ScimUser existingUser, UaaUser updatedUser) {
        updateUser(existingUser, updatedUser, true);
    }

    private void updateUser(ScimUser existingUser, UaaUser updatedUser, boolean updateGroups) {
        String id = existingUser.getId();
        logger.debug("Updating user account: " + updatedUser + " with SCIM Id: " + id);
        if (updateGroups) {
            logger.debug("Removing existing group memberships ...");
            Set<ScimGroup> existingGroups = membershipManager.getGroupsWithMember(id, true, IdentityZoneHolder.get().getId());

            for (ScimGroup g : existingGroups) {
                removeFromGroup(id, g.getDisplayName());
            }
        }

        final ScimUser newScimUser = convertToScimUser(updatedUser);
        newScimUser.setVersion(existingUser.getVersion());
        scimUserProvisioning.update(id, newScimUser, IdentityZoneHolder.get().getId());
        if (OriginKeys.UAA.equals(newScimUser.getOrigin()) && hasText(updatedUser.getPassword())) { //password is not relevant for non UAA users
            scimUserProvisioning.changePassword(id, null, updatedUser.getPassword(), IdentityZoneHolder.get().getId());
        }
        if (updateGroups) {
            Collection<String> newGroups = convertToGroups(updatedUser.getAuthorities());
            logger.debug("Adding new groups " + newGroups);
            addGroups(id, newGroups);
        }
    }

    private void createNewUser(UaaUser user) {
        logger.debug("Registering new user account: " + user);
        ScimUser newScimUser = scimUserProvisioning.createUser(convertToScimUser(user), user.getPassword(), IdentityZoneHolder.get().getId());
        addGroups(newScimUser.getId(), convertToGroups(user.getAuthorities()));
    }

    private void addGroups(String scimUserid, Collection<String> groups) {
        for (String group : groups) {
            addToGroup(scimUserid, group);
        }
    }

    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof AuthEvent) {
            onApplicationEvent((AuthEvent) event);
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

    private void updateScimUser(UaaUser uaaUser) {
        ScimUser user = getScimUser(uaaUser);
        if (user == null) {
            throw new RuntimeException("SCIM user not found for UAA user [" + uaaUser.getUsername() + "]");
        }
        updateUser(user, uaaUser, false);
    }

    public void onApplicationEvent(AuthEvent event) {
        UaaUser uaaUser = event.getUser();
        if (event instanceof InvitedUserAuthenticatedEvent) {
            // external users should default to not being verified
            if (!OriginKeys.UAA.equals(uaaUser.getOrigin())) {
                uaaUser.setVerified(false);
            }
            updateScimUser(uaaUser);
            return;
        }
        if (event instanceof ExternalGroupAuthorizationEvent) {
            ExternalGroupAuthorizationEvent exEvent = (ExternalGroupAuthorizationEvent) event;
            //delete previous membership relation ships
            String origin = exEvent.getUser().getOrigin();
            if (!OriginKeys.UAA.equals(origin)) {
                Set<ScimGroup> groupsWithMember = membershipManager.getGroupsWithExternalMember(exEvent.getUser().getId(), origin, IdentityZoneHolder.get().getId());
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
                    membershipManager.removeMemberById(group.getId(), exEvent.getUser().getId(), group.getZoneId());
                }
            }
            //update the user itself
            if (event.isUserModified()) {
                //update the user itself
                updateScimUser(uaaUser);
            }
            return;
        }

        if (event instanceof NewUserAuthenticatedEvent) {
            addUser(uaaUser);
        }
    }

    private void addToGroup(String scimUserId, String gName) {
        addToGroup(scimUserId, gName, OriginKeys.UAA, true);
    }

    private void addToGroup(String scimUserId, String gName, String origin, boolean addGroup) {
        if (!StringUtils.hasText(gName)) {
            return;
        }
        logger.debug("Adding to group: " + gName);
        List<ScimGroup> g = scimGroupProvisioning.query(String.format("displayName eq \"%s\"", gName), IdentityZoneHolder.get().getId());
        ScimGroup group;
        if ((g == null || g.isEmpty()) && (!addGroup)) {
            logger.debug("No group found with name:" + gName + ". Group membership will not be added.");
            return;
        } else if (g == null || g.isEmpty()) {
            group = new ScimGroup(null, gName, IdentityZoneHolder.get().getId());
            group = scimGroupProvisioning.create(group, IdentityZoneHolder.get().getId());
        } else {
            group = g.get(0);
        }
        try {
            ScimGroupMember groupMember = new ScimGroupMember(scimUserId);
            groupMember.setOrigin(origin);
            membershipManager.addMember(group.getId(), groupMember, IdentityZoneHolder.get().getId());
        } catch (MemberAlreadyExistsException ex) {
            // do nothing
        }
    }

    private void removeFromGroup(String scimUserId, String gName) {
        if (!StringUtils.hasText(gName)) {
            return;
        }
        logger.debug("Removing membership of group: " + gName);
        List<ScimGroup> g = scimGroupProvisioning.query(String.format("displayName eq \"%s\"", gName), IdentityZoneHolder.get().getId());
        ScimGroup group;
        if (g == null || g.isEmpty()) {
            return;
        } else {
            group = g.get(0);
        }
        try {
            membershipManager.removeMemberById(group.getId(), scimUserId, IdentityZoneHolder.get().getId());
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
