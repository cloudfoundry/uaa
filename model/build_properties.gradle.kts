import org.eclipse.jgit.storage.file.FileRepositoryBuilder
import org.eclipse.jgit.revwalk.RevWalk
import java.text.SimpleDateFormat
import java.util.Properties
import java.io.FileOutputStream

buildscript {
    repositories {
        mavenCentral()
    }

    dependencies {
        classpath(libs.eclipseJgit)
    }
}

tasks.register("mainOutputResourcesDir") {
    doLast {
        val mainSourceSet = project.extensions.getByType<SourceSetContainer>().named("main").get()
        mainSourceSet.output.resourcesDir?.mkdirs()
    }
}

tasks.register("gitInfo") {
    dependsOn("mainOutputResourcesDir")

    doLast {
        val props = Properties()
        try {
            val builder = FileRepositoryBuilder()
            builder.readEnvironment()
            if (builder.gitDir == null) {
                builder.findGitDir(projectDir)
            }
            val repository = builder.build()
            val objectId = repository.resolve("HEAD")
            val commit = RevWalk(repository).parseCommit(objectId)
            props.setProperty("git.commit.id.abbrev", commit.id.name.substring(0, 7))
            @Suppress("DEPRECATION")
            props.setProperty("git.commit.time", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(commit.authorIdent.getWhen()))
        } catch (e: Exception) {
            logger.warn("Exception raised while reading git metadata: $e")
            props.setProperty("git.commit.id.abbrev", "git-metadata-not-found")
            props.setProperty("git.commit.time", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(java.util.Date()))
        }
        val mainSourceSet = project.extensions.getByType<SourceSetContainer>().named("main").get()
        props.store(FileOutputStream("${mainSourceSet.resources.srcDirs.first()}/git.properties"), "DO NOT EDIT. This is generated file.")
    }
}

tasks.register("buildInfo") {
    dependsOn("mainOutputResourcesDir")

    doLast {
        val props = Properties()
        props.setProperty("build.version", version.toString())
        val mainSourceSet = project.extensions.getByType<SourceSetContainer>().named("main").get()
        props.store(FileOutputStream("${mainSourceSet.resources.srcDirs.first()}/build.properties"), "DO NOT EDIT. This is generated file.")
    }
}

tasks.named<ProcessResources>("processResources") {
    dependsOn("gitInfo", "buildInfo")
}