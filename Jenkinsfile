#!/usr/bin/env groovy

pipeline {
    agent {
        docker {
            image 'repo.ci.build.ge.com:8443/predix-security/uaa-ci-testing:0.0.4'
            label 'dind'
            args '-v /var/lib/docker/.gradle:/root/.gradle'
        }
    }
    environment {
        COMPLIANCEENABLED = true

    }
    options {
        skipDefaultCheckout()
        buildDiscarder(logRotator(artifactDaysToKeepStr: '1', artifactNumToKeepStr: '1', daysToKeepStr: '5', numToKeepStr: '10'))
    }
    stages {
        stage ('Checkout & Build') {
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
                expression { false }
            }
            steps {
                sh '''#!/bin/bash -ex
                        source uaa-cf-release/config-local/set-env.sh
                        unset HTTPS_PROXY
                        unset HTTP_PROXY
                        unset http_proxy
                        unset https_proxy
                        unset GRADLE_OPTS
                        pushd uaa
                            ./gradlew --continue :cloudfoundry-identity-server:test
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
                expression { true }
            }
            steps {
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
                ./gradlew --continue :cloudfoundry-identity-uaa:test
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
        stage('Integration Tests') {
            when {
                expression { false }
            }
            steps {
                sh '''#!/bin/bash -ex 
            source uaa-cf-release/config-local/set-env.sh
            unset HTTPS_PROXY
            unset HTTP_PROXY
            unset http_proxy
            unset https_proxy
            unset GRADLE_OPTS                    
            pushd uaa
               ./gradlew --continue jacocoRootReportIntegrationTest
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
            }
        }
        stage('Deploy to RC') {
            environment {
                CF_CREDENTIALS = credentials('CF_CREDENTIALS_CF3')
                ADMIN_CLIENT_SECRET = credentials('CF3_RELEASE_CANDIDATE_ADMIN_CLIENT_SECRET')
                DEPLOYMENT_TYPE = 'cf3-release-candidate'
                MAP_ROUTES_TO_DEPLOYED_APP = 'true'
            }
            steps {
                dir('build') {
                    unstash 'uaa-war'
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
                    
                    ./ci_deploy.sh
                    
                    # mvn deploy:deploy-file -DgroupId=org.cloudfoundry.identity \\
                    #    -DartifactId=cloudfoundry-identity-uaa \\
                    #    -Dversion=$APP_VERSION \\
                    #    -Dpackaging=war \\
                    #    -Dfile=../build/cloudfoundry-identity-uaa-$APP_VERSION.war \\
                    #    -DrepositoryId=artifactory.releases \\
                    #    -Durl=https://devcloud.swcoe.ge.com/artifactory/MAAXA-MVN \\
                    #    -Dartifactory.password=$ARTIFACTORY_PASSWORD \\
                    #    -s mvn_settings.xml \\
                    #    -B
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
    }
    post {
        success {
            echo 'Your Gradle pipeline was successful sending notification'
        }
        failure {
            echo "Your Gradle pipeline failed sending notification...."
        }

    }

}