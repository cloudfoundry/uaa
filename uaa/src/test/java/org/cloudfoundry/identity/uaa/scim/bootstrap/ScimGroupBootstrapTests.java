package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.MapPropertySource;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class ScimGroupBootstrapTests {
    private JdbcScimGroupProvisioning gDB;

    private JdbcScimUserProvisioning uDB;

    private JdbcScimGroupMembershipManager mDB;

    private ScimGroupBootstrap bootstrap;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void initScimGroupBootstrapTests() {
        JdbcTemplate template = jdbcTemplate;
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
        gDB = new JdbcScimGroupProvisioning(template, pagingListFactory);
        uDB = new JdbcScimUserProvisioning(template, pagingListFactory, passwordEncoder);
        mDB = new JdbcScimGroupMembershipManager(template, new TimeServiceImpl(), uDB, null);
        mDB.setScimGroupProvisioning(gDB);

        uDB.deleteByIdentityZone(IdentityZone.getUaaZoneId());
        gDB.deleteByIdentityZone(IdentityZone.getUaaZoneId());

        uDB.createUser(TestUtils.scimUserInstance("dev1"), "test", IdentityZone.getUaaZoneId());
        uDB.createUser(TestUtils.scimUserInstance("dev2"), "test", IdentityZone.getUaaZoneId());
        uDB.createUser(TestUtils.scimUserInstance("dev3"), "test", IdentityZone.getUaaZoneId());
        uDB.createUser(TestUtils.scimUserInstance("qa1"), "test", IdentityZone.getUaaZoneId());
        uDB.createUser(TestUtils.scimUserInstance("qa2"), "test", IdentityZone.getUaaZoneId());
        uDB.createUser(TestUtils.scimUserInstance("mgr1"), "test", IdentityZone.getUaaZoneId());
        uDB.createUser(TestUtils.scimUserInstance("hr1"), "test", IdentityZone.getUaaZoneId());

        assertEquals(7, uDB.retrieveAll(IdentityZone.getUaaZoneId()).size());
        assertEquals(0, gDB.retrieveAll(IdentityZone.getUaaZoneId()).size());

        bootstrap = new ScimGroupBootstrap(gDB, uDB, mDB);
    }

    @Test
    void canAddGroups() throws Exception {
        bootstrap.setGroups(StringUtils.commaDelimitedListToSet("org1.dev,org1.qa,org1.engg,org1.mgr,org1.hr").stream().collect(new MapCollector<>(s -> s, s -> null)));
        bootstrap.afterPropertiesSet();
        assertEquals(5, gDB.retrieveAll(IdentityZone.getUaaZoneId()).size());
        assertNotNull(bootstrap.getGroup("org1.dev"));
        assertNotNull(bootstrap.getGroup("org1.qa"));
        assertNotNull(bootstrap.getGroup("org1.engg"));
        assertNotNull(bootstrap.getGroup("org1.mgr"));
        assertNotNull(bootstrap.getGroup("org1.hr"));
    }

    @Test
    void allowsBootstrapFromOtherInstance() throws Exception {
        //original bootstrap
        bootstrap.setGroups(StringUtils.commaDelimitedListToSet("multiple_bootstrap_group").stream().collect(new MapCollector<>(s -> s, s -> null)));
        bootstrap.afterPropertiesSet();

        //mock external bootstrap in between getOrCreate and update calls
        ScimGroup multipleBootstrapGroupBefore = bootstrap.getGroup("multiple_bootstrap_group");
        ScimGroup multipleBootstrapGroupAfter = bootstrap.getGroup("multiple_bootstrap_group");
        multipleBootstrapGroupAfter.setVersion(multipleBootstrapGroupAfter.getVersion() + 1);

        gDB = mock(JdbcScimGroupProvisioning.class);
        when(gDB.create(any(), anyString())).thenReturn(multipleBootstrapGroupBefore);
        when(gDB.createOrGet(any(), anyString())).thenReturn(multipleBootstrapGroupBefore);
        when(gDB.update(anyString(), any(), anyString())).thenThrow(new IncorrectResultSizeDataAccessException(1, 0));
        when(gDB.getByName(anyString(), anyString())).thenReturn(multipleBootstrapGroupAfter);

        //second bootstrap
        bootstrap = new ScimGroupBootstrap(gDB, uDB, mDB);
        bootstrap.setGroups(StringUtils.commaDelimitedListToSet("multiple_bootstrap_group").stream().collect(new MapCollector<>(s -> s, s -> s)));
        bootstrap.afterPropertiesSet();

        assertNotNull(bootstrap.getGroup("multiple_bootstrap_group"));
    }

    @Test
    void testNullGroups() throws Exception {
        bootstrap.setGroups(null);
        bootstrap.afterPropertiesSet();
        assertEquals(0, gDB.retrieveAll(IdentityZone.getUaaZoneId()).size());
    }

    @Test
    void canAddMembers() throws Exception {
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(emptyList());

        bootstrap.setGroupMembers(Arrays.asList(
                "org1.dev|dev1,dev2,dev3",
                "org1.dev|hr1,mgr1|write",
                "org1.qa|qa1,qa2,qa3",
                "org1.mgr|mgr1",
                "org1.hr|hr1",
                "org1.engg|org1.dev,org1.qa,org1.mgr"
        ));
        bootstrap.afterPropertiesSet();

        assertEquals(5, gDB.retrieveAll(IdentityZone.getUaaZoneId()).size());
        assertEquals(7, uDB.retrieveAll(IdentityZone.getUaaZoneId()).size());
        assertEquals(2, bootstrap.getGroup("org1.qa").getMembers().size());
        assertEquals(1, bootstrap.getGroup("org1.hr").getMembers().size());
        assertEquals(3, bootstrap.getGroup("org1.engg").getMembers().size());
        assertEquals(5, mDB.getMembers(bootstrap.getGroup("org1.dev").getId(), false, IdentityZone.getUaaZoneId()).size());
    }

    @Test
    void stripsWhitespaceFromGroupNamesAndDescriptions() throws Exception {
        Map<String, String> groups = new HashMap<>();
        groups.put("print", "Access the network printer");
        groups.put("   something", "        Do something else");
        bootstrap.setGroups(groups);
        bootstrap.afterPropertiesSet();

        ScimGroup group;
        assertNotNull(group = bootstrap.getGroup("something"));
        assertNotNull(group = gDB.retrieve(group.getId(), IdentityZone.getUaaZoneId()));
        assertEquals("something", group.getDisplayName());
        assertEquals("Do something else", group.getDescription());
    }

    @Test
    void fallsBackToMessagesProperties() throws Exception {
        // set up default groups
        HashMap<String, Object> defaultDescriptions = new HashMap<>();
        defaultDescriptions.put("pets.cat", "Access the cat");
        defaultDescriptions.put("pets.dog", "Dog your data");
        defaultDescriptions.put("pony", "The magic of friendship");
        bootstrap.setMessageSource(new MapPropertySource("messages.properties", defaultDescriptions));

        bootstrap.setMessagePropertyNameTemplate("%s");
        bootstrap.setNonDefaultUserGroups(Collections.singleton("pets.cat"));
        bootstrap.setDefaultUserGroups(Collections.singleton("pets.dog"));

        Map<String, String> groups = new HashMap<>();
        groups.put("pony", "");
        bootstrap.setGroups(groups);

        bootstrap.afterPropertiesSet();

        List<ScimGroup> bootstrappedGroups = gDB.retrieveAll(IdentityZone.getUaaZoneId());

        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "pets.cat".equals(group.getDisplayName()) && "Access the cat".equals(group.getDescription())));
        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "pets.dog".equals(group.getDisplayName()) && "Dog your data".equals(group.getDescription())));
        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "pony".equals(group.getDisplayName()) && "The magic of friendship".equals(group.getDescription())));

    }

    @Test
    void prefersNonBlankYmlOverMessagesProperties() throws Exception {
        // set up default groups
        HashMap<String, Object> defaults = new HashMap<>();
        defaults.put("records.read", "");
        defaults.put("pets.cat", "Access the cat");
        defaults.put("pets.dog", "Dog your data");

        HashMap<String, Object> nonDefaultUserGroups = new HashMap<>();
        nonDefaultUserGroups.put("water.drink", "hint");

        bootstrap.setMessageSource(new MapPropertySource("messages.properties", defaults));
        bootstrap.setMessagePropertyNameTemplate("%s");
        bootstrap.setNonDefaultUserGroups(nonDefaultUserGroups.keySet());
        bootstrap.setDefaultUserGroups(defaults.keySet());

        Map<String, String> groups = new HashMap<>();
        groups.put("print", "Access the network printer");
        groups.put("records.read", "Read important data");
        groups.put("pets.cat", "Pet the cat");
        groups.put("pets.dog", null);
        groups.put("fish.nemo", null);
        groups.put("water.drink", "Drink the water");
        // set up configured groups
        bootstrap.setGroups(groups);

        bootstrap.afterPropertiesSet();

        List<ScimGroup> bootstrappedGroups = gDB.retrieveAll(IdentityZone.getUaaZoneId());

        // print: only specified in the configured groups, so it should get its description from there
        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "print".equals(group.getDisplayName()) && "Access the network printer".equals(group.getDescription())));
        // records.read: exists in the message property source but should get its description from configuration
        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "records.read".equals(group.getDisplayName()) && "Read important data".equals(group.getDescription())));
        // pets.cat: read: exists in the message property source but should get its description from configuration
        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "pets.cat".equals(group.getDisplayName()) && "Pet the cat".equals(group.getDescription())));
        // pets.dog: specified in configuration with no description, so it should retain the default description
        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "pets.dog".equals(group.getDisplayName()) && "Dog your data".equals(group.getDescription())));
        // fish.nemo: never gets a description
        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "fish.nemo".equals(group.getDisplayName()) && group.getDescription() == null));
        assertThat(bootstrappedGroups, PredicateMatcher.has(group -> "water.drink".equals(group.getDisplayName()) && "Drink the water".equals(group.getDescription())));
    }
}
