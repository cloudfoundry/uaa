#!/usr/bin/env groovy
def buildGeArtServer = Artifactory.server('build.ge')

@Library(['PPCmanifest','security-ci-commons-shared-lib']) _
def NODE = nodeDetails("uaa-upgrade")

pipeline {
    agent none
    environment {
        COMPLIANCEENABLED = true
    }
    options {
        timestamps()
        skipDefaultCheckout()
        buildDiscarder(logRotator(artifactNumToKeepStr: '30', numToKeepStr: '30'))
    }
    parameters {
        booleanParam(name: 'UNIT_TESTS', defaultValue: true, description: 'Run Unit tests')
        booleanParam(name: 'MOCK_MVC_TESTS', defaultValue: true, description: 'Run Mock MVC tests')
        booleanParam(name: 'INTEGRATION_TESTS', defaultValue: true, description: 'Run Integration tests')
        booleanParam(name: 'DEGRADED_TESTS', defaultValue: true, description: 'Run degraded mode tests')
        booleanParam(name: 'PUSH_TO_BUILD_GE', defaultValue: false, description: 'Publish to build artifactory')
        string(name: 'UAA_CI_CONFIG_BRANCH', defaultValue: 'master',
                        description: 'uaa-cf-release repo branch to use for testing/deployment')
        booleanParam(name: 'TRIGGER_GESOS_IMAGE_BUILD', defaultValue: false,
                                description: 'If enabled, triggers a GE SOS image build (needs corresponding branch in iam-container-config repo)')
    }
    stages {
        stage('Build and run Tests') {
            parallel {
                stage ('Checkout & Build') {
                    agent {
                        docker {
                            image "${NODE['IMAGE']}"
                            label "${NODE['LABEL']}"
                            args "${NODE['ARGS']}"
                        }
                    }
                    steps {
                        echo env.BRANCH_NAME
                        dir('uaa-cf-release') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/uaa-cf-release.git',
                                branch: params.UAA_CI_CONFIG_BRANCH
                        }
                        dir('uaa') {
                            checkout scm
                        }
                        dir('uaa/iam-k8s-utils') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/iam-k8s-utils.git'
                        }
                        sh '''#!/bin/bash -ex
                            source uaa-cf-release/config-local/set-env.sh
                            unset HTTPS_PROXY
                            unset HTTP_PROXY
                            unset http_proxy
                            unset https_proxy
                            unset GRADLE_OPTS
                            pushd uaa
                                ./gradlew clean assemble
                            popd
                        '''
                        dir('uaa/uaa/build/libs') {
                            stash includes: '*.war', name: 'uaa-war'
                        }
                    }
                    post {
                        success {
                            echo "Gradle Checkout & Build stage completed"
                        }
                        failure {
                            echo "Gradle Checkout & Build stage failed"
                        }
                    }
                }
                stage('Unit Tests') {
                    when {
                        expression { params.UNIT_TESTS == true }
                    }
                    agent {
                        docker {
                            image "${NODE['IMAGE']}"
                            label "${NODE['LABEL']}"
                            args "${NODE['ARGS']}"
                        }
                    }
                    steps {
                        echo env.BRANCH_NAME
                        dir('uaa-cf-release') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/uaa-cf-release.git',
                                branch: params.UAA_CI_CONFIG_BRANCH
                        }
                        dir('uaa') {
                            checkout scm
                        }
                        dir('uaa/iam-k8s-utils') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/iam-k8s-utils.git'
                        }
                        sh '''#!/bin/bash -ex
                                source uaa-cf-release/config-local/set-env.sh
                                unset HTTPS_PROXY
                                unset HTTP_PROXY
                                unset http_proxy
                                unset https_proxy
                                unset GRADLE_OPTS
                                pushd uaa
                                    ./gradlew --no-daemon --continue jacocoRootReportServerTest
                                popd
                                '''
                    }
                    post {
                        success {
                            echo "Unit tests completed"
                        }
                        failure {
                            echo "Unit tests failed"
                        }
                        always {
                            junit testResults: 'uaa/server/build/test-results/**/*.xml', allowEmptyResults: true
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/server/build/reports/tests/test',
                                reportFiles: 'index.html',
                                reportName: 'Unit Test Results'
                            ]
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/build/reports/jacoco/jacocoRootReportServerTest/html',
                                reportFiles: 'index.html',
                                reportName: 'Unit Test Code Coverage'
                            ]
                        }
                    }
                }
                stage('Mockmvc Tests') {
                    when {
                        expression { params.MOCK_MVC_TESTS == true }
                    }
                    agent {
                        docker {
                            image "${NODE['IMAGE']}"
                            label "${NODE['LABEL']}"
                            args "${NODE['ARGS']}"
                        }
                    }
                    steps {
                        echo env.BRANCH_NAME
                        dir('uaa-cf-release') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/uaa-cf-release.git',
                                branch: params.UAA_CI_CONFIG_BRANCH
                        }
                        dir('uaa') {
                            checkout scm
                        }
                        dir('uaa/iam-k8s-utils') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/iam-k8s-utils.git'
                        }
                        sh '''#!/bin/bash -ex
                            source uaa-cf-release/config-local/set-env.sh
                            unset HTTPS_PROXY
                            unset HTTP_PROXY
                            unset http_proxy
                            unset https_proxy
                            unset GRADLE_OPTS
                            pushd uaa
                                apt-get -qy install lsof
                                ./gradlew --no-daemon --continue jacocoRootReportUaaTest
                            popd
                            '''
                    }
                    post {
                        success {
                            echo "mockmvc tests completed"
                        }
                        failure {
                            echo "mockmvc tests failed"
                        }
                        always {
                            junit testResults: 'uaa/uaa/build/test-results/**/*.xml', allowEmptyResults: true
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/uaa/build/reports/tests/test',
                                reportFiles: 'index.html',
                                reportName: 'MockMvc Test Results'
                            ]
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/build/reports/jacoco/jacocoRootReportUaaTest/html',
                                reportFiles: 'index.html',
                                reportName: 'MockMvc Test Code Coverage'
                            ]
                        }
                    }
                }
            }
        }
        stage('Integration and Degraded Mode Tests') {
            parallel {
                stage('Integration Tests') {
                    when {
                        expression { params.INTEGRATION_TESTS == true }
                    }
                    agent {
                        docker {
                            image "${NODE['IMAGE']}"
                            label "${NODE['LABEL']}"
                            args '-v /var/lib/docker/.gradle:/root/.gradle --add-host "zone-with-cors-policy.localhost testzone1.localhost testzone2.localhost int-test-zone-uaa.localhost testzone3.localhost testzone4.localhost testzonedoesnotexist.localhost testzoneinactive.localhost oidcloginit.localhost test-zone1.localhost test-zone2.localhost test-victim-zone.localhost test-platform-zone.localhost test-saml-zone.localhost test-app-zone.localhost app-zone.localhost platform-zone.localhost testsomeother2.ip.com testsomeother.ip.com uaa-acceptance-zone.localhost orchestrator-int-test-zone.localhost localhost":127.0.0.1'
                        }
                    }
                    steps {
                        echo env.BRANCH_NAME
                        dir('uaa-cf-release') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/uaa-cf-release.git',
                                branch: params.UAA_CI_CONFIG_BRANCH
                        }
                        dir('uaa') {
                            checkout scm
                        }
                        dir('uaa/iam-k8s-utils') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/iam-k8s-utils.git'
                        }

                        sh '''#!/bin/bash -ex

                            source uaa/scripts/setup-tests.sh

                            ### verify dns set
                            cat /etc/hosts

                            ### set env
                            source uaa-cf-release/config-local/set-env.sh
                            unset_env

                            curl -v http://simplesamlphp.uaa-acceptance.cf-app.com/saml2/idp/metadata.php

                            ### start slapd and add entries to ldap for tests
                            /etc/init.d/slapd start
                            /etc/init.d/slapd status
                            ldapadd -Y EXTERNAL -H ldapi:/// -f uaa/uaa/src/test/resources/ldap_db_init.ldif
                            ldapadd -x -D 'cn=admin,dc=test,dc=com' -w password -f uaa/uaa/src/test/resources/ldap_init.ldif

                            ### run integration tests
                            pushd uaa
                               ./gradlew --no-daemon --continue jacocoRootReportIntegrationTest
                            popd

                            '''
                    }
                    post {
                        success {
                            echo "integration tests completed"
                        }
                        failure {
                            echo "integration tests failed"
                        }
                        always {
                            junit testResults: 'uaa/uaa/build/test-results/**/*.xml', allowEmptyResults: true
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/uaa/build/reports/tests/integrationTest',
                                reportFiles: 'index.html',
                                reportName: 'Integration Test Results'
                            ]
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/build/reports/jacoco/jacocoRootReportIntegrationTest/html',
                                reportFiles: 'index.html',
                                reportName: 'Integration Test Code Coverage'
                            ]
                        }
                    }
                }
                stage('Degraded Mode Tests') {
                    when {
                        expression { params.DEGRADED_TESTS == true }
                    }
                    environment {
                        CF_CREDENTIALS = credentials("CF_CREDENTIALS_CF3_RELEASE_CANDIDATE")
                        ADMIN_CLIENT_SECRET = credentials("ADMIN_CLIENT_SECRET_CF3_INTEGRATION")
                        SPLUNK_OTEL_ACCESS_TOKEN = credentials("SPLUNK_OTEL_ACCESS_TOKEN")
                    }
                    agent {
                        docker {
                            image "${NODE['IMAGE']}"
                            label "${NODE['LABEL']}"
                            args "${NODE['ARGS']}"
                        }
                    }
                    steps {
                        echo env.BRANCH_NAME
                        dir('uaa-cf-release') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/uaa-cf-release.git',
                                branch: params.UAA_CI_CONFIG_BRANCH
                        }
                        dir('uaa') {
                            checkout scm
                        }
                        dir('uaa/iam-k8s-utils') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                                url: 'https://github.build.ge.com/predix/iam-k8s-utils.git'
                        }

                        sh '''#!/bin/bash -ex
                            #### Only run degraded tests for branches that are post 3.20.1 and do have the version in the name
                            export BRANCH_VERSION=`echo $BRANCH_NAME | grep -Eo '[0-9.]+'`
                            if [ -z $BRANCH_VERSION ]; then
                                echo "Ignoring DEGRADED tests for this branch"
                            else
                                export MAJOR_VERSION=`echo $BRANCH_VERSION | cut -d'.' -f1`
                                if [ "$MAJOR_VERSION" -gt 3 ]; then

                                    source uaa/scripts/setup-tests.sh

                                    #Configure the credentials for cf3-integration to be used
                                    echo "Updating CF username and password for cf3-integration!"
                                    export CF_USERNAME=$CF_CREDENTIALS_USR
                                    export CF_PASSWORD=$CF_CREDENTIALS_PSW
                                    #Hard code the DEPLOYMENT_TYPE to cf3-integration as only this environment is set up to run the degraded tests
                                    export DEPLOYMENT_TYPE=cf3-integration

                                    #Set up env
                                    source uaa-cf-release/config-cf3-integration/set-env.sh
                                    #Overriding what is set in the set-env.sh
                                    export APP_VERSION=`grep 'version' uaa/gradle.properties | sed 's/version=//'`
                                    unset_env

                                    ruby -v

                                    # The docker image comes with uaac version 4.1.0, which is fine.
                                    # DO NOT upgrade to 4.2.0, for that version url-encodes special characters, turning
                                    # admin secret abc@def into abc%40def, which leads to a "Bad credentials"
                                    # authentication failure.
                                    uaac --version

                                    apt-get install jq -y
                                    jq --version

                                    if [[ "$BRANCH_NAME" == "predix_extensions"* || "$BRANCH_NAME" == "PR-"* ]]; then
                                        echo "Ignoring degraded JWT cloud tests for this branch"
                                        export DEGRADED_TEST_ARGS='--dont-run-jwt-cloud-tests'
                                    fi
                                    echo 'DEGRADED_TEST_ARGS=$DEGRADED_TEST_ARGS'

                                    export JRE_VERSION="{ jre: { version: 11.+ }}"

                                    ./uaa-cf-release/uaa-degraded-tests-cf.sh $DEGRADED_TEST_ARGS
                                fi
                            fi
                            '''
                    }
                    post {
                        success {
                            echo "degraded mode tests completed"
                        }
                        failure {
                            echo "degraded mode tests failed"
                        }
                        always {
                            junit testResults: 'uaa/uaa/build/test-results/**/*.xml', allowEmptyResults: true
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/uaa/build/reports/tests/degradedTestCloud',
                                reportFiles: 'index.html',
                                reportName: 'Degraded Mode Test Results'
                            ]
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/uaa/build/reports/tests/degradedJwtTestCloud',
                                reportFiles: 'index.html',
                                reportName: 'Jwt Degraded Mode Test Results'
                            ]
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/build/reports/jacoco/jacocoRootReportDegradedCloudTest/html',
                                reportFiles: 'index.html',
                                reportName: 'Degraded Mode Test Code Coverage'
                            ]
                            publishHTML target: [
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: 'uaa/build/reports/jacoco/jacocoRootReportDegradedJwtCloudTest/html',
                                reportFiles: 'index.html',
                                reportName: 'Jwt Degraded Mode Test Code Coverage'
                            ]
                        }
                    }
                }
            }
        }
        stage('Build PR image and publish to ECR') {
            when {
                // Image build and push for rc and release branches is done using GE SOS Build pipeline
                // See gesos-image-build.pipeline triggered using Post-Build Script stage
                changeRequest()
            }
            agent {
                docker {
                    image "${NODE['IMAGE']}"
                    label "${NODE['LABEL']}"
                    args "${NODE['ARGS']} -v /var/run/docker.sock:/var/run/docker.sock"
                }
            }
            environment {
                AWS_ECR_SSO_CREDENTIALS = credentials('AWS_ECR_SSO_CREDENTIALS')
            }
            steps {
                dir('iam-container-config') {
                    // Check out repo with Dockerfiles and build/publish script
                    git changelog: false,
                            credentialsId: 'github.build.ge.com',
                            poll: false,
                            url: 'https://github.build.ge.com/predix/iam-container-config.git',
                            branch: 'master'

                    unstash 'uaa-war'
                    script {
                        sh """
                            # Copy war file for copying into container image when building
                            cp cloudfoundry-identity-uaa*.war uaa/cloudfoundry-identity-uaa.war

                            ./container-build-publish uaa
                        """
                    }
                }
            }
            post {
                success {
                    echo "Build PR image and publish to ECR completed"
                }
                failure {
                    echo "Build PR image and publish to ECR failed"
                }
            }
        }
        stage('Upload Build Artifact') {
            agent {
                label 'dind'
            }
            when {
                expression { params.PUSH_TO_BUILD_GE == true }
            }
            steps{
                dir('uaa') {
                    checkout scm
                }
                dir('uaa/iam-k8s-utils') {
                    git changelog: false, credentialsId: 'github.build.ge.com', poll: false,
                        url: 'https://github.build.ge.com/predix/iam-k8s-utils.git'
                }
                dir('build') {
                    unstash 'uaa-war'
                }

                script {
                    def util = load('uaa/JenkinsfileCommon.groovy')
                    ARTIFACTORY_PATH = util.getArtifactoryPath()
                    WAR_FILE_NAME = util.getWarFileName()
                    sh """
                        ls -l "build/${WAR_FILE_NAME}" || \
                        (echo "build/${WAR_FILE_NAME} not found!" && ls -l build && exit 1)
                    """
                    def uploadSpec = """{
                       "files": [
                           {
                               "pattern": "build/${WAR_FILE_NAME}",
                               "target": "${ARTIFACTORY_PATH}/"
                           }
                       ]
                    }"""

                    echo "Uploading ${WAR_FILE_NAME} to ${ARTIFACTORY_PATH}/"
                    def buildInfo = buildGeArtServer.upload(uploadSpec)
                    buildGeArtServer.publishBuildInfo(buildInfo)
                }
            }
            post {
                success {
                    echo "Upload Build Artifact completed"
                }
                failure {
                    echo "Upload Build Artifact failed"
                }
            }
        }
    }
    post {
        success {
            echo 'UAA pipeline was successful. Sending notification!'

            // Trigger GE SOS build job for uaa image build
            script {
                if (params.TRIGGER_GESOS_IMAGE_BUILD && (BRANCH_NAME.matches('rc_[\\d.]+') || BRANCH_NAME.matches('release_[\\d.]+'))) {
                    imageTag = BRANCH_NAME
                    if (imageTag.matches('release_[\\d.]+')) {
                        imageTag = imageTag.replaceAll('release_', '')
                    }
            	    build job: JOB_NAME.replaceAll('/Build n Test/', '/GE SOS Build/'),
                    propagate: false,
                    wait: false,
                    parameters: [
                        string(name: 'IAM_CONTAINER_CONFIG_BRANCH_NAME', value: BRANCH_NAME),
                        string(name: 'IMAGE_TAG', value: imageTag)
                    ]
            	}
            }
        }
        failure {
            echo "UAA pipeline failed. Sending notification!"
        }
    }

}
