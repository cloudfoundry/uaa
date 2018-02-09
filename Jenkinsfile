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
        booleanParam(name: 'UNIT_TESTS', defaultValue: true, description: 'Run Unit tests')
        booleanParam(name: 'MOCK_MVC_TESTS', defaultValue: true, description: 'Run Mock MVC tests')
        booleanParam(name: 'INTEGRATION_TESTS', defaultValue: true, description: 'Run Integration tests')
        booleanParam(name: 'BUILD_TO_STAGE', defaultValue: false, description: 'Publish to build artifactory')
    }
    stages {
        stage('Build and run Tests') {
            parallel {
                stage ('Checkout & Build') {
                    agent {
                      docker {
                          image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.7'
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
                        expression { params.UNIT_TESTS == true }
                    }
                    agent {
                        docker {
                            image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.7'
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
                        expression { params.MOCK_MVC_TESTS == true }
                    }
                    agent {
                        docker {
                            image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.7'
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
                expression { params.INTEGRATION_TESTS == true }
            }
            agent {
                docker {
                    image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.7'
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
                expression { params.BUILD_TO_STAGE == true }
            }
            steps{
                dir('uaa') {
                    checkout scm
                }
                dir('build') {
                        unstash 'uaa-war'
                }
                script {
                    APP_VERSION = sh (returnStdout: true, script: '''
                        grep 'version' uaa/gradle.properties | sed 's/version=//'
                        ''').trim()
                    echo "Uploading UAA ${APP_VERSION} build to Artifactory"
                    def uploadSpec = """{
                        "files": [
                            {
                                "pattern": "build/cloudfoundry-identity-uaa-${APP_VERSION}.war",
                                "target": "MAAXA-MVN/builds/uaa/${APP_VERSION}/"
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