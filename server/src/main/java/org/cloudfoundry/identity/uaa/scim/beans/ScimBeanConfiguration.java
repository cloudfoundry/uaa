package org.cloudfoundry.identity.uaa.scim.beans;

import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.account.event.PasswordChangeEventPublisher;
import org.cloudfoundry.identity.uaa.impl.config.ScimExternalGroupsTypeResolvingFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.ScimGroupsTypeResolvingFactoryBean;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimUserBootstrap;
import org.cloudfoundry.identity.uaa.scim.event.ScimEventPublisher;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.services.ScimUserService;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserEditor;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class ScimBeanConfiguration {

    @Bean("self")
    public IsSelfCheck self(
            @Qualifier("revocableTokenProvisioning") RevocableTokenProvisioning tokenProvisioning
    ) {
        return new IsSelfCheck(tokenProvisioning);
    }

    @Bean("globalPasswordPolicy")
    public PasswordPolicy globalPasswordPolicy(
            @Value("${password.policy.global.minLength:0}") int minLength,
            @Value("${password.policy.global.maxLength:255}") int maxLength,
            @Value("${password.policy.global.requireUpperCaseCharacter:0}") int requireUpperCaseCharacter,
            @Value("${password.policy.global.requireLowerCaseCharacter:0}") int requireLowerCaseCharacter,
            @Value("${password.policy.global.requireDigit:0}") int requireDigit,
            @Value("${password.policy.global.requireSpecialCharacter:0}") int requireSpecialCharacter,
            @Value("${password.policy.global.expirePasswordInMonths:0}") int expirePasswordInMonths

    ) {
        return new PasswordPolicy(
                minLength,
                maxLength,
                requireUpperCaseCharacter,
                requireLowerCaseCharacter,
                requireDigit,
                requireSpecialCharacter,
                expirePasswordInMonths
        );
    }

    @Bean("defaultUaaPasswordPolicy")
    public PasswordPolicy defaultUaaPasswordPolicy(
            @Value("${password.policy.minLength:#{globalPasswordPolicy.getMinLength()}}") int minLength,
            @Value("${password.policy.maxLength:#{globalPasswordPolicy.getMaxLength()}}") int maxLength,
            @Value("${password.policy.requireUpperCaseCharacter:#{globalPasswordPolicy.getRequireUpperCaseCharacter()}}") int requireUpperCaseCharacter,
            @Value("${password.policy.requireLowerCaseCharacter:#{globalPasswordPolicy.getRequireLowerCaseCharacter()}}") int requireLowerCaseCharacter,
            @Value("${password.policy.requireDigit:#{globalPasswordPolicy.getRequireDigit()}}") int requireDigit,
            @Value("${password.policy.requireSpecialCharacter:#{globalPasswordPolicy.getRequireSpecialCharacter()}}") int requireSpecialCharacter,
            @Value("${password.policy.expirePasswordInMonths:#{globalPasswordPolicy.getExpirePasswordInMonths()}}") int expirePasswordInMonths

    ) {
        return new PasswordPolicy(
                minLength,
                maxLength,
                requireUpperCaseCharacter,
                requireLowerCaseCharacter,
                requireDigit,
                requireSpecialCharacter,
                expirePasswordInMonths
        );
    }


    @Bean
    public Set<String> nonDefaultUserGroups() {
        return Sets.newHashSet(
                "scim.read",
                "scim.write",
                "scim.invite",
                "uaa.resource",
                "uaa.admin",
                "clients.read",
                "clients.write",
                "clients.secret",
                "cloud_controller.admin",
                "clients.admin",
                "zones.write"
        );
    }

    @Bean(name = "exceptionToStatusMap")
    public Map<Class<? extends Exception>, HttpStatus> exceptionToStatusMap() {
        Map<Class<? extends Exception>, HttpStatus> map = new LinkedHashMap<>();
        map.put(org.springframework.dao.DataAccessException.class, HttpStatus.UNPROCESSABLE_ENTITY);
        map.put(org.springframework.dao.DataIntegrityViolationException.class, HttpStatus.BAD_REQUEST);
        map.put(org.springframework.http.converter.HttpMessageConversionException.class, HttpStatus.BAD_REQUEST);
        map.put(org.springframework.web.HttpMediaTypeException.class, HttpStatus.BAD_REQUEST);
        map.put(java.lang.IllegalArgumentException.class, HttpStatus.BAD_REQUEST);
        map.put(java.lang.UnsupportedOperationException.class, HttpStatus.BAD_REQUEST);
        map.put(org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException.class, HttpStatus.BAD_REQUEST);
        map.put(org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException.class, HttpStatus.BAD_REQUEST);
        map.put(org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException.class, HttpStatus.NOT_FOUND);
        map.put(org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException.class, HttpStatus.CONFLICT);
        map.put(org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException.class, HttpStatus.CONFLICT);
        map.put(org.springframework.jdbc.BadSqlGrammarException.class, HttpStatus.BAD_REQUEST);

        return Collections.unmodifiableMap(map);
    }

    @Bean
    public PasswordChangeEventPublisher passwordEventPublisher(
            @Qualifier("scimUserProvisioning") ScimUserProvisioning scimUserProvisioning,
            @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager
    ) {
        return new PasswordChangeEventPublisher(scimUserProvisioning, identityZoneManager);
    }

    @Bean(name = "scimEventPublisher")
    public ScimEventPublisher scimEventPublisher(@Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager) {
        return new ScimEventPublisher(identityZoneManager);
    }

    @Bean(name = "scimGroupProvisioning")
    @Lazy
    public JdbcScimGroupProvisioning scimGroupProvisioning(
            final NamedParameterJdbcTemplate namedJdbcTemplate,
            final JdbcPagingListFactory pagingListFactory,
            final DbUtils dbUtils,
            @Lazy @Qualifier("externalGroupMembershipManager") JdbcScimGroupExternalMembershipManager externalMembershipManager,
            @Lazy @Qualifier("groupMembershipManager") JdbcScimGroupMembershipManager groupMembershipManager,
            @Qualifier("identityZoneProvisioning") JdbcIdentityZoneProvisioning identityZoneProvisioning
    ) throws SQLException {
        JdbcScimGroupProvisioning bean = new JdbcScimGroupProvisioning(namedJdbcTemplate, pagingListFactory, dbUtils);
        bean.setJdbcScimGroupExternalMembershipManager(externalMembershipManager);
        bean.setJdbcScimGroupMembershipManager(groupMembershipManager);
        bean.setJdbcIdentityZoneProvisioning(identityZoneProvisioning);
        return bean;
    }

    @Bean(name = "externalGroupMembershipManager")
    @Lazy
    public JdbcScimGroupExternalMembershipManager externalGroupMembershipManager(
            JdbcTemplate jdbcTemplate,
            DbUtils dbUtils,
            @Qualifier("scimGroupProvisioning") ScimGroupProvisioning scimGroupProvisioning
    ) throws SQLException {
        JdbcScimGroupExternalMembershipManager bean = new JdbcScimGroupExternalMembershipManager(jdbcTemplate, dbUtils);
        bean.setScimGroupProvisioning(scimGroupProvisioning);
        return bean;
    }

    @Bean(name = "groupMembershipManager")
    public JdbcScimGroupMembershipManager groupMembershipManager(
            @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
            final JdbcTemplate jdbcTemplate,
            final TimeService timeService,
            final IdentityZoneProvisioning identityZoneProvisioning,
            final DbUtils dbUtils,
            @Qualifier("scimUserProvisioning") ScimUserProvisioning scimUserProvisioning,
            @Qualifier("scimGroupProvisioning") ScimGroupProvisioning scimGroupProvisioning
    ) throws SQLException {
        JdbcScimGroupMembershipManager bean = new JdbcScimGroupMembershipManager(
                identityZoneManager,
                jdbcTemplate,
                timeService,
                scimUserProvisioning,
                identityZoneProvisioning,
                dbUtils
        );
        bean.setScimGroupProvisioning(scimGroupProvisioning);
        return bean;
    }

    @Bean("users")
    public List<String> users(
            @Value("#{(@config['scim']==null or @config['scim']['users']==null)?@hack_emptyList:@config['scim']['users']}") List<String> users
    ) {
        return users;
    }

    @Bean("scimUserBootstrap")
    public ScimUserBootstrap scimUserBootstrap(
            @Qualifier("scimUserProvisioning") ScimUserProvisioning scimUserProvisioning,
            ScimUserService scimUserService,
            @Qualifier("scimGroupProvisioning") ScimGroupProvisioning scimGroupProvisioning,
            @Qualifier("groupMembershipManager") ScimGroupMembershipManager membershipManager,
            @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
            @Qualifier("users") List<String> users,
            @Value("${scim.user.override:false}") final boolean override,
            @Value("${delete.users:#{null}}") final List<String> usersToDelete,
            @Qualifier("aliasEntitiesEnabled") final boolean aliasEntitiesEnabled
    ) {
        UaaUserEditor editor = new UaaUserEditor();
        List<UaaUser> uaaUsers = new LinkedList<>();
        for (String s : users) {
            editor.setAsText(s);
            uaaUsers.add((UaaUser) editor.getValue());
        }

        ScimUserBootstrap scimUserBootstrap = new ScimUserBootstrap(
                scimUserProvisioning,
                scimUserService,
                scimGroupProvisioning,
                membershipManager,
                identityZoneManager,
                uaaUsers,
                override,
                usersToDelete,
                aliasEntitiesEnabled
        );

        return scimUserBootstrap;
    }

    @Bean("scimGroupBootstrap")
    public ScimGroupBootstrap scimGroupBootstrap(
            @Qualifier("scimUserProvisioning") ScimUserProvisioning scimUserProvisioning,
            @Qualifier("scimGroupProvisioning") ScimGroupProvisioning scimGroupProvisioning,
            @Qualifier("groupMembershipManager") ScimGroupMembershipManager scimGroupMembershipManager,
            @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
            @Qualifier("groups") HashMap<String, String> groups,
            @Qualifier("members") List<String> members,
            @Qualifier("defaultUserAuthorities") Set<String> defaultUserGroups,
            @Qualifier("nonDefaultUserGroups") Set<String> nonDefaultUserGroups) {
        ScimGroupBootstrap scimGroupBootstrap = new ScimGroupBootstrap(
                scimGroupProvisioning,
                scimUserProvisioning,
                scimGroupMembershipManager,
                identityZoneManager
        );
        scimGroupBootstrap.setGroups(groups);
        scimGroupBootstrap.setGroupMembers(members);
        scimGroupBootstrap.setDefaultUserGroups(defaultUserGroups);
        scimGroupBootstrap.setNonDefaultUserGroups(nonDefaultUserGroups);
        return scimGroupBootstrap;
    }

    @Bean("scimExternalGroupBootstrap")
    public ScimExternalGroupBootstrap scimExternalGroupBootstrap(
            @Qualifier("scimGroupProvisioning") ScimGroupProvisioning scimGroupProvisioning,
            @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager scimGroupExternalMembershipManager,
            @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
            @Qualifier("externalGroups") Map<String, Map<String, List>> externalGroups) {
        ScimExternalGroupBootstrap scimExternalGroupBootstrap = new ScimExternalGroupBootstrap(
                scimGroupProvisioning,
                scimGroupExternalMembershipManager,
                identityZoneManager
        );
        scimExternalGroupBootstrap.setExternalGroupMaps(externalGroups);
        scimExternalGroupBootstrap.setAddNonExistingGroups(true);
        return scimExternalGroupBootstrap;
    }

    @Bean("members")
    public List<String> members(
            @Value("#{(@config['scim']==null or @config['scim']['group_membership']==null)?@hack_emptyList:@config['scim']['group_membership']}") List<String> m
    ) {
        return m;
    }

    @Bean("groups")
    public HashMap<String, String> groups(
            @Value("#{(@config['scim']==null or @config['scim']['groups']==null) ? '' : @config['scim']['groups']}") Object o
    ) {
        return new ScimGroupsTypeResolvingFactoryBean(o).getGroups();
    }

    @Bean("hack_emptyList")
    public List hack_emptyList() {
        return Collections.emptyList();
    }

    @Bean("externalGroups")
    public Map<String, Map<String, List>> externalGroups(
            @Value("#{(@config['scim']==null or @config['scim']['external_groups']==null)?@hack_emptyList:@config['scim']['external_groups']}") Object config
    ) {
        return new ScimExternalGroupsTypeResolvingFactoryBean(config).getExternalGroups();
    }

}
