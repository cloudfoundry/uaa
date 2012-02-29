/**
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
import com.excilys.ebi.gatling.app.Gatling
import com.excilys.ebi.gatling.core.util.PathHelper.path2string
import com.excilys.ebi.gatling.app.Options

object Engine extends App {

	Gatling.start(Options(
		dataFolder = Some(IDEPathHelper.dataFolder),
		resultsFolder = Some(IDEPathHelper.resultsFolder),
		requestBodiesFolder = Some(IDEPathHelper.requestBodiesFolder),
		simulationBinariesFolder = Some(IDEPathHelper.mavenBinariesDir)))
}