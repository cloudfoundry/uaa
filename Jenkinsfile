#!/usr/bin/env groovy
def devcloudArtServer = Artifactory.server('devcloud')
pipeline {
    agent none
    environment {
            COMPLIANCEENABLED = true
    }
    options {
        skipDefaultCheckout()
        buildDiscarder(logRotator(artifactDaysToKeepStr: '1', artifactNumToKeepStr: '1', daysToKeepStr: '5', numToKeepStr: '10'))
    }
    parameters {
        choice(name: 'DEPLOYMENT_TYPE', choices:'cf3-release-candidate\ncf3-staging\ncf3-sysint\ncf3-integration\nvpc\njpn\neu-central\nazr-usw\nasv-pr\nperf-vpc-sb\nperf-asv-sb\nperf-cf3\nvpc-db-mig-test\nasv-sb', description: 'This specifies which point of presence to deploy to')
        booleanParam(name: 'MAP_ROUTES_TO_DEPLOYED_APP', defaultValue: true, description: 'Determines if the published routes are mapped to the newly deployed app. Defaults to true.')
        booleanParam(name: 'DEPLOY', defaultValue: false, description: 'Determines whether to deploy UAA to CF3 release candidate.')
        booleanParam(name: 'RUN_ACCEPTANCE_TESTS', defaultValue: true, description: 'Determines whether to run the acceptance test against the freshly deployed UAA.')
    }
    stages {
        stage('Build and run Tests') {
            parallel {
                stage ('Checkout & Build') {
                    when {
                        expression { params.DEPLOYMENT_TYPE == 'cf3-release-candidate' }

                    }
                    agent {
                      docker {
                          image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.5'
                          label 'dind'
                          args '-v /var/lib/docker/.gradle:/root/.gradle'
                      }
                    }
                    steps {
                        echo env.BRANCH_NAME
                        dir('uaa-cf-release') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false, url: 'https://github.build.ge.com/predix/uaa-cf-release.git', branch: 'feature/jenkinsfile'
                        }
                        dir('uaa') {
                            checkout scm
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
                        expression { params.DEPLOYMENT_TYPE == 'cf3-release-candidate' }
                    }
                    agent {
                        docker {
                            image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.5'
                            label 'dind'
                            args '-v /var/lib/docker/.gradle:/root/.gradle'
                        }
                    }
                    steps {
                        echo env.BRANCH_NAME
                        dir('uaa-cf-release') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false, url: 'https://github.build.ge.com/predix/uaa-cf-release.git', branch: 'feature/jenkinsfile'
                        }
                        dir('uaa') {
                            checkout scm
                        }
                        sh '''#!/bin/bash -ex
                                source uaa-cf-release/config-local/set-env.sh
                                unset HTTPS_PROXY
                                unset HTTP_PROXY
                                unset http_proxy
                                unset https_proxy
                                unset GRADLE_OPTS
                                pushd uaa
                                    ./gradlew --no-daemon --continue :cloudfoundry-identity-server:test
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
                    }
                }
                stage('Mockmvc Tests') {
                    when {
                        expression { params.DEPLOYMENT_TYPE == 'cf3-release-candidate' }
                    }
                    agent {
                        docker {
                            image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.5'
                            label 'dind'
                            args '-v /var/lib/docker/.gradle:/root/.gradle'
                        }
                    }
                    steps {
                        echo env.BRANCH_NAME
                        dir('uaa-cf-release') {
                            git changelog: false, credentialsId: 'github.build.ge.com', poll: false, url: 'https://github.build.ge.com/predix/uaa-cf-release.git', branch: 'feature/jenkinsfile'
                        }
                        dir('uaa') {
                            checkout scm
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
                                ./scripts/travis/install-ldap-certs.sh
                                ./gradlew --no-daemon --continue :cloudfoundry-identity-uaa:test
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
                    }
                }
            }
        }
        stage('Integration Tests') {
            when {
                expression { params.DEPLOYMENT_TYPE == 'cf3-release-candidate' }
            }
            agent {
                docker {
                    image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.5'
                    label 'dind'
                    args '-v /var/lib/docker/.gradle:/root/.gradle --add-host "testzone1.localhost testzone2.localhost int-test-zone-uaa.localhost testzone3.localhost testzone4.localhost testzonedoesnotexist.localhost oidcloginit.localhost test-zone1.localhost test-zone2.localhost test-victim-zone.localhost test-platform-zone.localhost test-saml-zone.localhost test-app-zone.localhost app-zone.localhost platform-zone.localhost testsomeother2.ip.com testsomeother.ip.com uaa-acceptance-zone.localhost localhost":127.0.0.1'
                }
            }
            steps {
                echo env.BRANCH_NAME
                dir('uaa-cf-release') {
                    git changelog: false, credentialsId: 'github.build.ge.com', poll: false, url: 'https://github.build.ge.com/predix/uaa-cf-release.git', branch: 'feature/jenkinsfile'
                }
                dir('uaa') {
                    checkout scm
                }
                sh '''#!/bin/bash -ex
                    source uaa-cf-release/config-local/set-env.sh
                    unset HTTPS_PROXY
                    unset HTTP_PROXY
                    unset http_proxy
                    unset https_proxy
                    unset GRADLE_OPTS
                    unset DEFAULT_JVM_OPTS
                    unset JAVA_PROXY_OPTS
                    unset PROXY_PORT
                    unset PROXY_HOST
                    cat /etc/hosts
                    curl -v http://simplesamlphp2.cfapps.io/saml2/idp/metadata.php
                    curl -v http://simplesamlphp2.cfapps.io/saml2/idp/metadata.php
                    pushd uaa
                        env
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
                    archiveArtifacts 'uaa/uaa/build/reports/tests/**'
                }
            }
        }
        stage('Upload Build Artifact') {
            agent {
                label 'dind'
            }
            when {
                expression { params.DEPLOYMENT_TYPE == 'cf3-release-candidate' }
            }
            steps{
                dir('uaa') {
                    checkout scm
                }
                script {
                    APP_VERSION = sh (returnStdout: true, script: '''
                        grep 'version' uaa/gradle.properties | sed 's/version=//'
                        ''').trim()
                    echo "Uploading UAA ${APP_VERSION} build to Artifactory"
                    dir('build') {
                        unstash 'uaa-war'
                    }
                    def uploadSpec = """{
                        "files": [
                            {
                                "pattern": "build/uaa/cloudfoundry-identity-uaa-${APP_VERSION}.war",
                                "target": "MAAXA-MVN/builds/uaa/${APP_VERSION}/"
                            }
                        ]
                    }"""
                    def buildInfo = devcloudArtServer.upload(uploadSpec)
                    devcloudArtServer.publishBuildInfo(buildInfo)
                }
            }
        }
        stage('Deploy') {
            agent{
                docker {
                    image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.5'
                    label 'dind'
                    args '-v /var/lib/docker/.gradle:/root/.gradle'
                }
            }
            when {
                expression { params.DEPLOY == true }
            }
            environment {
                CF_CREDENTIALS = credentials("CF_CREDENTIALS_${DEPLOYMENT_TYPE.toUpperCase().replaceAll('-','_')}")
                ADMIN_CLIENT_SECRET = credentials("ADMIN_CLIENT_SECRET_${DEPLOYMENT_TYPE.toUpperCase().replaceAll('-','_')}")
            }
            steps {
                script {
                    echo "CF_CREDENTIALS $CF_CREDENTIALS_USR"
                    echo "Downloading UAA  ${APP_VERSION} Artifact Artifactory"
                    def downloadSpec = """{
                        "files": [
                            {
                                "target": "deploy-workspace/",
                                "flat": "true",
                                "pattern": "MAAXA-MVN/builds/uaa/${APP_VERSION}/*.war"
                            }
                        ]
                    }"""
                    sh 'pwd && ls -ltr'
                    devcloudArtServer.download(downloadSpec)
                    sh "ls -ltr deploy-workspace/"
                }
                dir('uaa-cf-release') {
                    git changelog: false, credentialsId: 'github.build.ge.com', poll: false, url: 'https://github.build.ge.com/predix/uaa-cf-release.git', branch: 'feature/jenkinsfile'
                }
                sh '''#!/bin/bash -ex
                export CF_USERNAME=$CF_CREDENTIALS_USR
                export CF_PASSWORD=$CF_CREDENTIALS_PSW
                export SKIP_ACCEPTANCE_TESTS=true
                export APP_VERSION=`grep 'version' uaa/gradle.properties | sed 's/version=//'`
                echo "APP_VERSION is:$APP_VERSION"
                export DEPLOY_BRANCH_SUFFIX=$APP_VERSION
                source uaa-cf-release/config-${DEPLOYMENT_TYPE}/set-env.sh
                unset HTTPS_PROXY
                unset HTTP_PROXY
                unset http_proxy
                unset https_proxy
                unset GRADLE_OPTS

                pushd uaa-cf-release
                    source combine-inline-config.sh
                    echo "$UAA_CONFIG_YAML"
                    echo "$APP_NAME"
                    export UAA_CONFIG_COMMIT=`git rev-parse HEAD`
                    cf -v
                    ruby -v
                    ./ci_deploy.sh

                    if [ $DEPLOYMENT_TYPE != 'perf-vpc-sb' -a $DEPLOYMENT_TYPE != 'perf-asv-sb' -a $DEPLOYMENT_TYPE != 'perf-cf3' -a $DEPLOYMENT_TYPE != 'perf-azr-usw' -a $DEPLOYMENT_TYPE != 'cf3-integration' -a $DEPLOYMENT_TYPE != 'asv-pr-db-mig-test' ]; then
                        ./uaa-sb-acceptance-tests.sh
                    fi
                popd
                touch uaa-release.properties
                echo "DEPLOYMENT_TYPE:$DEPLOYMENT_TYPE" >> uaa-release.properties
                echo "UAA_CF_RELEASE_COMMIT_HASH:$UAA_CONFIG_COMMIT" >> uaa-release.properties
                echo "UAA_APP_VERSION:$APP_VERSION" >> uaa-release.properties
                '''
                stash includes: 'uaa-release.properties', name:'uaa-release.properties'
            }
        }
        stage('Upload Uaa Artifact') {
            agent {
                label 'dind'
            }
            when {
                expression { params.DEPLOYMENT_TYPE == 'cf3-staging' }
            }
            steps{
                dir('uaa') {
                    checkout scm
                }
                script {
                    APP_VERSION = sh (returnStdout: true, script: '''
                        grep 'version' uaa/gradle.properties | sed 's/version=//'
                        ''').trim()
                    echo "Publishing UAA ${APP_VERSION} Artifact to Artifactory"
                    dir('build') {
                        unstash 'uaa-war'
                    }
                    def uploadSpec = """{
                        "files": [
                            {
                                "pattern": "build/cloudfoundry-identity-uaa-${APP_VERSION}.war",
                                "target": "MAAXA-MVN/org/cloudfoundry/identity/cloudfoundry-identity-uaa/${APP_VERSION}/"
                            }
                        ]
                    }"""
                    def buildInfo = devcloudArtServer.upload(uploadSpec)
                    devcloudArtServer.publishBuildInfo(buildInfo)
                }
            }
        }
    }
    post {
        success {
            echo 'UAA pipeline was successful. Sending notification!'
        }
        failure {
            echo "UAA pipeline failed. Sending notification!"
        }

    }

}