package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.extensions.SpringProfileCleanupExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringProfileCleanupExtension.class)
class LimitSqlAdapterFactoryTest {

    static class LimitSqlAdapterArgumentsProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(null, HsqlDbLimitSqlAdapter.class),
                    Arguments.of(emptyList(), HsqlDbLimitSqlAdapter.class),

                    Arguments.of(Collections.singletonList("hsqldb"), HsqlDbLimitSqlAdapter.class),
                    Arguments.of(Arrays.asList("hsqldb", "ldap"), HsqlDbLimitSqlAdapter.class),
                    Arguments.of(Arrays.asList("ldap", "hsqldb"), HsqlDbLimitSqlAdapter.class),

                    Arguments.of(Collections.singletonList("postgresql"), PostgresLimitSqlAdapter.class),
                    Arguments.of(Arrays.asList("postgresql", "ldap"), PostgresLimitSqlAdapter.class),
                    Arguments.of(Arrays.asList("ldap", "postgresql"), PostgresLimitSqlAdapter.class),

                    Arguments.of(Collections.singletonList("mysql"), MySqlLimitSqlAdapter.class),
                    Arguments.of(Arrays.asList("mysql", "ldap"), MySqlLimitSqlAdapter.class),
                    Arguments.of(Arrays.asList("ldap", "mysql"), MySqlLimitSqlAdapter.class),

                    Arguments.of(Arrays.asList("hsqldb", "mysql", "postgresql", "ldap"), PostgresLimitSqlAdapter.class),
                    Arguments.of(Arrays.asList("hsqldb", "mysql", "ldap"), MySqlLimitSqlAdapter.class),
                    Arguments.of(Arrays.asList("hsqldb", "ldap"), HsqlDbLimitSqlAdapter.class),
                    Arguments.of(Collections.singletonList("hsqldb"), HsqlDbLimitSqlAdapter.class),

                    Arguments.of(Collections.singletonList("anything"), HsqlDbLimitSqlAdapter.class)
            );
        }
    }

    @ParameterizedTest
    @ArgumentsSource(LimitSqlAdapterArgumentsProvider.class)
    void getLimitSqlAdapter(List<String> profiles, Class<?> expectedClazz) {
        if (profiles == null) {
            System.clearProperty("spring.profiles.active");
        } else {
            System.setProperty("spring.profiles.active", StringUtils.join(profiles, ","));
        }

        assertThat(LimitSqlAdapterFactory.getLimitSqlAdapter().getClass()).isSameAs(expectedClazz);
    }

    @ParameterizedTest
    @ArgumentsSource(LimitSqlAdapterArgumentsProvider.class)
    void getLimitSqlAdapter_withStringProfiles(List<String> profiles, Class<?> expectedClazz) {
        assertThat(LimitSqlAdapterFactory.getLimitSqlAdapter(StringUtils.join(profiles, ",")).getClass()).isSameAs(expectedClazz);
    }

    @ParameterizedTest
    @ArgumentsSource(LimitSqlAdapterArgumentsProvider.class)
    void getLimitSqlAdapter_withListProfiles(List<String> profiles, Class<?> expectedClazz) {
        assertThat(LimitSqlAdapterFactory.getLimitSqlAdapter(profiles).getClass()).isSameAs(expectedClazz);
    }

}