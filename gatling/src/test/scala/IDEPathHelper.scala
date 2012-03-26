/*
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
import scala.tools.nsc.io.File
import scala.tools.nsc.io.Path
object IDEPathHelper {

	val gatlingConfUrl = getClass.getClassLoader.getResource("gatling.conf").getPath
	val projectRootDir = File(gatlingConfUrl).parents(2)

	val mavenSourcesDir = projectRootDir / "src" / "main" / "scala"
	val mavenResourcesDir = projectRootDir / "src" / "main" / "resources"
	val mavenTargetDir = projectRootDir / "target"
	val mavenBinariesDir = mavenTargetDir / "classes"

	val dataFolder = mavenResourcesDir / "data"
	val requestBodiesFolder = mavenResourcesDir / "request-bodies"

	val recorderOutputFolder = mavenSourcesDir / Path("${package}".split("."))
	val resultsFolder = mavenTargetDir / "gatling-results"
}