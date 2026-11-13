package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.event.ScimEventPublisher;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class ScimGroupPaginationTests {

    @Autowired
    private NamedParameterJdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    private JdbcScimGroupProvisioning dao;
    private ScimGroupEndpoints endpoints;
    private ScimGroupMembershipManager memberships;
    private final AtomicInteger mappedRows = new AtomicInteger();
    private String zoneId;

    @BeforeEach
    void setUp() throws SQLException {
        zoneId = UUID.randomUUID().toString();
        JdbcPagingListFactory factory = new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter) {
            @Override
            public <T> List<T> createJdbcPagingList(String sql, Map<String, ?> args, RowMapper<T> mapper, int pageSize) {
                return super.createJdbcPagingList(sql, args, (rs, rowNum) -> {
                    mappedRows.incrementAndGet();
                    return mapper.mapRow(rs, rowNum);
                }, pageSize);
            }
        };
        dao = new JdbcScimGroupProvisioning(jdbcTemplate, factory, new DbUtils());
        JdbcIdentityZoneProvisioning zoneProvisioning = mock(JdbcIdentityZoneProvisioning.class);
        IdentityZone zone = new IdentityZone();
        zone.setId(zoneId);
        when(zoneProvisioning.retrieve(zoneId)).thenReturn(zone);
        dao.setJdbcIdentityZoneProvisioning(zoneProvisioning);
        memberships = mock(ScimGroupMembershipManager.class);
        when(memberships.getMembers(anyString(), eq(false), eq(zoneId)))
                .thenReturn(List.of(new ScimGroupMember("member")));
        IdentityZoneManager zones = mock(IdentityZoneManager.class);
        when(zones.getCurrentIdentityZoneId()).thenReturn(zoneId);
        endpoints = new ScimGroupEndpoints(dao, memberships, zones, 20, Map.of(), null,
                mock(ScimEventPublisher.class), null);
        List.of("uaa.user", "uaa.resource", "uaa.none", "uaa.admin")
                .forEach(name -> dao.create(new ScimGroup(null, name, zoneId), zoneId));
        IntStream.range(0, 246)
                .forEach(i -> dao.create(new ScimGroup(null, "page-" + i, zoneId), zoneId));
        mappedRows.set(0);
    }

    @AfterEach
    void tearDown() {
        dao.deleteByIdentityZone(zoneId);
    }

    @Test
    void oneGroupRequestMapsOneRowAndKeepsTotal() {
        SearchResults<?> result = endpoints.listGroups("id", "id pr", "id", "ascending", 1, 1);

        assertThat(result.getResources()).hasSize(1);
        assertThat(result.getTotalResults()).isEqualTo(250);
        assertThat(mappedRows).hasValue(1);
        verifyNoInteractions(memberships);
    }

    @Test
    void configuredMaximumBoundsDatabaseFetch() {
        SearchResults<?> result = endpoints.listGroups("id", "id pr", "id", "ascending", 1, 1000);

        assertThat(result.getResources()).hasSize(20);
        assertThat(result.getItemsPerPage()).isEqualTo(20);
        assertThat(result.getTotalResults()).isEqualTo(250);
        assertThat(mappedRows).hasValue(20);
    }

    @ParameterizedTest
    @CsvSource({"1, 0", "1000, 1", "1000, 0"})
    void emptyPageKeepsTotalWithoutMappingRows(int startIndex, int count) {
        SearchResults<?> result = endpoints.listGroups("id", "id pr", "id", "ascending", startIndex, count);

        assertThat(result.getResources()).isEmpty();
        assertThat(result.getTotalResults()).isEqualTo(250);
        assertThat(mappedRows).hasValue(0);
        verifyNoInteractions(memberships);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "id,displayName", "id,displayName,members"})
    void laterPagePreservesFilterSortAndMembershipProjection(String attributes) {
        SearchResults<?> result = endpoints.listGroups(attributes,
                "displayName sw \"uaa.\"", "displayName", "descending", 2, 1);

        assertThat(result.getTotalResults()).isEqualTo(4);
        assertThat(result.getStartIndex()).isEqualTo(2);
        assertThat(result.getResources()).hasSize(1);
        assertThat(mappedRows).hasValue(1);
        Object group = result.getResources().getFirst();
        if (group instanceof ScimGroup scimGroup) {
            assertThat(scimGroup.getDisplayName()).isEqualTo("uaa.resource");
            assertThat(scimGroup.getMembers()).hasSize(1);
        } else {
            Map<?, ?> projection = (Map<?, ?>) group;
            assertThat(projection.get("displayName")).isEqualTo("uaa.resource");
            if (attributes.contains("members")) {
                assertThat((List<?>) projection.get("members")).hasSize(1);
            }
        }
        if (attributes.isEmpty() || attributes.contains("members")) {
            verify(memberships).getMembers(anyString(), eq(false), eq(zoneId));
        } else {
            verifyNoInteractions(memberships);
        }
    }
}
