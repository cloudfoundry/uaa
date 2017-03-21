package org.cloudfoundry.identity.uaa.db;


 import javax.sql.DataSource;

 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 import org.springframework.beans.factory.annotation.Value;
 import org.springframework.cloud.config.java.AbstractCloudConfig;
 import org.springframework.cloud.service.PooledServiceConnectorConfig.PoolConfig;
 import org.springframework.cloud.service.relational.DataSourceConfig;
 import org.springframework.cloud.service.relational.DataSourceConfig.ConnectionConfig;
 import org.springframework.context.annotation.Bean;
 import org.springframework.context.annotation.Configuration;
 import org.springframework.context.annotation.Profile;
 import org.springframework.transaction.PlatformTransactionManager;

 import java.util.Arrays;
 import java.util.List;

 /**
  * DataSourceConfig used for all cloud profiles.
  */
 @Configuration
 @Profile({ "cloud" })
 public class CloudDataSourceConfig extends AbstractCloudConfig {
     private static final Logger LOGGER = LoggerFactory.getLogger(CloudDataSourceConfig.class);

     @Value("${UAA_DB}")
     private String uaaDb;
     @Value("${MIN_ACTIVE:30}")
     private int minActive;
     @Value("${MAX_ACTIVE:100}")
     private int maxActive;
     @Value("${MAX_WAIT_TIME:30000}")
     private int maxWaitTime;


     @Bean
     public DataSourceConfig dataSourceConfig() {
         PoolConfig poolConfig = new PoolConfig(this.minActive, this.maxActive, this.maxWaitTime);
         ConnectionConfig connect = new ConnectionConfig("charset=utf-8");
         List<String> dataSourceNames = Arrays.asList("TomcatJdbc", "BasicDbcp");
         return new DataSourceConfig(poolConfig, connect, dataSourceNames);
     }

     @Bean
     public DataSource dataSource() {
         LOGGER.info("Starting UAA with the database that is bound to it:" + this.uaaDb);
         DataSource ds = connectionFactory().dataSource(this.uaaDb, dataSourceConfig());
         LOGGER.info("************ DataSource info: " + ds.getClass().getCanonicalName());
         return ds;
     }


 }