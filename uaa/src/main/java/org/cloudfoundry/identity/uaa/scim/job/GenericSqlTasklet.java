/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.scim.job;

import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * @author Dave Syer
 * 
 */
public class GenericSqlTasklet implements Tasklet {

	private JdbcOperations jdbcTemplate;

	private String sql;

	public void setDataSource(DataSource dataSource) {
		jdbcTemplate = new JdbcTemplate(dataSource);
	}

	public void setSql(String sql) {
		this.sql = sql;
	}

	@Override
	public RepeatStatus execute(StepContribution contribution, ChunkContext chunkContext) throws Exception {
		if (sql == null) {
			return RepeatStatus.FINISHED;
		}
		if (sql.toLowerCase().startsWith("select")) {
			List<Map<String, Object>> list = jdbcTemplate.queryForList(sql);
			String result = list.toString();
			chunkContext.getStepContext().getStepExecution().getJobExecution().getExecutionContext()
					.put("result", result.substring(0, Math.min(result.length(), 4096)));
		} else {
			int updated = jdbcTemplate.update(sql);
			contribution.incrementWriteCount(updated);
		}
		return RepeatStatus.FINISHED;
	}

}
