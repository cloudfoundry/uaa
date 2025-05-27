package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.MapPropertySource;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
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
    NamedParameterJdbcTemplate namedJdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void initScimGroupBootstrapTests() throws SQLException {
        JdbcTemplate template = jdbcTemplate;
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter);
        DbUtils dbUtils = new DbUtils();
        gDB = new JdbcScimGroupProvisioning(namedJdbcTemplate, pagingListFactory, dbUtils);
        uDB = new JdbcScimUserProvisioning(namedJdbcTemplate, pagingListFactory, passwordEncoder, new IdentityZoneManagerImpl(), new JdbcIdentityZoneProvisioning(jdbcTemplate), new SimpleSearchQueryConverter(), new SimpleSearchQueryConverter(), new TimeServiceImpl(), true);
        mDB = new JdbcScimGroupMembershipManager(new IdentityZoneManagerImpl(), template, new TimeServiceImpl(), uDB, null, dbUtils);
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

        assertThat(uDB.retrieveAll(IdentityZone.getUaaZoneId())).hasSize(7);
        assertThat(gDB.retrieveAll(IdentityZone.getUaaZoneId())).isEmpty();

        bootstrap = new ScimGroupBootstrap(gDB, uDB, mDB, new IdentityZoneManagerImpl());
    }

    @Test
    void canAddGroups() {
        bootstrap.setGroups(StringUtils.commaDelimitedListToSet("org1.dev,org1.qa,org1.engg,org1.mgr,org1.hr").stream().collect(new MapCollector<>(s -> s, s -> null)));
        bootstrap.afterPropertiesSet();
        assertThat(gDB.retrieveAll(IdentityZone.getUaaZoneId())).hasSize(5);
        assertThat(bootstrap.getGroup("org1.dev")).isNotNull();
        assertThat(bootstrap.getGroup("org1.qa")).isNotNull();
        assertThat(bootstrap.getGroup("org1.engg")).isNotNull();
        assertThat(bootstrap.getGroup("org1.mgr")).isNotNull();
        assertThat(bootstrap.getGroup("org1.hr")).isNotNull();
    }

    @Test
    void allowsBootstrapFromOtherInstance() {
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
        bootstrap = new ScimGroupBootstrap(gDB, uDB, mDB, new IdentityZoneManagerImpl());
        bootstrap.setGroups(StringUtils.commaDelimitedListToSet("multiple_bootstrap_group").stream().collect(new MapCollector<>(s -> s, s -> s)));
        bootstrap.afterPropertiesSet();

        assertThat(bootstrap.getGroup("multiple_bootstrap_group")).isNotNull();
    }

    @Test
    void nullGroups() {
        bootstrap.setGroups(null);
        bootstrap.afterPropertiesSet();
        assertThat(gDB.retrieveAll(IdentityZone.getUaaZoneId())).isEmpty();
    }

    @Test
    void canAddMembers() {
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

        assertThat(gDB.retrieveAll(IdentityZone.getUaaZoneId())).hasSize(5);
        assertThat(uDB.retrieveAll(IdentityZone.getUaaZoneId())).hasSize(7);
        assertThat(bootstrap.getGroup("org1.qa").getMembers()).hasSize(2);
        assertThat(bootstrap.getGroup("org1.hr").getMembers()).hasSize(1);
        assertThat(bootstrap.getGroup("org1.engg").getMembers()).hasSize(3);
        assertThat(mDB.getMembers(bootstrap.getGroup("org1.dev").getId(), false, IdentityZone.getUaaZoneId())).hasSize(5);
    }

    @Test
    void stripsWhitespaceFromGroupNamesAndDescriptions() {
        Map<String, String> groups = new HashMap<>();
        groups.put("print", "Access the network printer");
        groups.put("   something", "        Do something else");
        bootstrap.setGroups(groups);
        bootstrap.afterPropertiesSet();

        ScimGroup group;
        assertThat(group = bootstrap.getGroup("something")).isNotNull();
        assertThat(group = gDB.retrieve(group.getId(), IdentityZone.getUaaZoneId())).isNotNull();
        assertThat(group.getDisplayName()).isEqualTo("something");
        assertThat(group.getDescription()).isEqualTo("Do something else");
    }

    @Test
    void fallsBackToMessagesProperties() {
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

        assertThat(bootstrappedGroups).extracting(ScimGroup::getDisplayName, ScimGroup::getDescription)
                .contains(tuple("pets.cat", "Access the cat"),
                        tuple("pets.dog", "Dog your data"),
                        tuple("pony", "The magic of friendship"));
    }

    @Test
    void prefersNonBlankYmlOverMessagesProperties() {
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

        assertThat(bootstrappedGroups).extracting(ScimGroup::getDisplayName, ScimGroup::getDescription)
                .containsExactlyInAnyOrder(
                        // print: only specified in the configured groups, so it should get its description from there
                        tuple("print", "Access the network printer"),
                        // records.read: exists in the message property source but should get its description from configuration
                        tuple("records.read", "Read important data"),
                        // pets.cat: read: exists in the message property source but should get its description from configuration
                        tuple("pets.cat", "Pet the cat"),
                        // pets.dog: specified in configuration with no description, so it should retain the default description
                        tuple("pets.dog", "Dog your data"),
                        // fish.nemo: never gets a description
                        tuple("fish.nemo", null),
                        tuple("water.drink", "Drink the water")
                );
    }
}
