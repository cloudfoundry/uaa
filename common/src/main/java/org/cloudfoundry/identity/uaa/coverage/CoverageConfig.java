package org.cloudfoundry.identity.uaa.coverage;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;

@Configuration
public class CoverageConfig {

    public static final String COBERTURA_PROJECT_DATA_CLASSNAME = "net.sourceforge.cobertura.coveragedata.ProjectData";

    @Bean
    @Conditional(CoverageConfig.CoberturaCondition.class)
    public CoverageController coverageController() {
        return new CoverageController();
    }

    public static class CoberturaCondition implements Condition{
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            try {
                Class.forName(COBERTURA_PROJECT_DATA_CLASSNAME);
                return true;
            } catch (ClassNotFoundException e) {
                return false;
            }
        }
    }
}
