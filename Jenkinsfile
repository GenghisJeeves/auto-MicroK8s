pipeline {
    agent {
        label 'docker'
    }

    environment {
        DOCKER_IMAGE = 'ubuntu-microk8s-test'
        SNAP_NAME = 'auto-microk8s-cluster'
        SNAP_PATH = "${WORKSPACE}/snaps/${SNAP_NAME}"
    }

    stages {
        stage('Setup') {
            steps {
                echo 'Setting up build environment'
                sh 'sudo snap install snapcraft --classic || echo "snapcraft already installed"'
                sh 'sudo snap install lxd || echo "lxd already installed"'
                sh 'sudo snap install docker || echo "docker already installed"'
                
                // Make sure we have the latest code
                checkout scm
            }
        }

        stage('Create Ubuntu 24.04 Docker Image') {
            steps {
                echo 'Creating Ubuntu 24.04 Docker image'
                
                // Create a Dockerfile for Ubuntu 24.04 with snapd
                writeFile file: 'Dockerfile.ubuntu', text: '''
                FROM ubuntu:24.04
                
                # Install necessary packages
                RUN apt-get update && apt-get install -y \
                    snapd \
                    sudo \
                    systemd \
                    curl \
                    apt-transport-https \
                    ca-certificates \
                    --no-install-recommends \
                    && apt-get clean \
                    && rm -rf /var/lib/apt/lists/*
                
                # Set up systemd
                RUN cd /lib/systemd/system/sysinit.target.wants/ \
                    && rm $(ls | grep -v systemd-tmpfiles-setup)
                
                RUN systemctl enable snapd
                
                # Create a non-root user for testing
                RUN useradd -m -s /bin/bash ubuntu && \
                    echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu
                
                # Add working directory
                WORKDIR /home/ubuntu
                USER ubuntu
                
                # Use systemd as entrypoint
                ENTRYPOINT ["/lib/systemd/systemd"]
                '''
                
                // Build the Docker image
                sh 'docker build -t ${DOCKER_IMAGE} -f Dockerfile.ubuntu .'
            }
        }

        stage('Build Snap Package') {
            steps {
                echo 'Building auto-microk8s-cluster snap package'
                dir("${SNAP_PATH}") {
                    // Build the snap package
                    sh 'snapcraft --use-lxd'
                }
                
                // Save the snap filename
                script {
                    env.SNAP_FILE = sh(
                        script: "ls ${SNAP_PATH}/*.snap | head -1",
                        returnStdout: true
                    ).trim()
                    echo "Built snap package: ${env.SNAP_FILE}"
                }
            }
        }

        stage('Install and Test Snap in Docker Container') {
            steps {
                echo 'Running Docker container with systemd to test snap'
                
                // Run Docker with systemd and privileged mode (required for snap)
                sh '''
                docker run -d --privileged --name ubuntu-test \
                    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
                    -v ${SNAP_FILE}:/home/ubuntu/snap-package.snap \
                    ${DOCKER_IMAGE}
                '''
                
                // Wait for system to initialize
                sh 'sleep 30'
                
                // Install the snap package inside the Docker container
                sh '''
                docker exec ubuntu-test bash -c "sudo snap install --dangerous /home/ubuntu/snap-package.snap"
                '''
                
                // Wait for the snap to start
                sh 'sleep 10'
                
                // Verify the snap is running
                sh '''
                docker exec ubuntu-test bash -c "snap list | grep auto-microk8s-cluster"
                docker exec ubuntu-test bash -c "snap services | grep auto-microk8s-cluster"
                '''
                
                // Test functionality
                sh '''
                docker exec ubuntu-test bash -c "curl -s http://localhost:8800/ || echo 'Service not reachable'"
                '''
                
                // Collect logs for debugging
                sh '''
                docker exec ubuntu-test bash -c "snap logs auto-microk8s-cluster -n=100 || echo 'No logs available'"
                '''
            }
            post {
                always {
                    // Always stop and remove the container after testing
                    sh 'docker stop ubuntu-test || true'
                    sh 'docker rm ubuntu-test || true'
                }
            }
        }
        
        stage('Package Release') {
            when {
                branch 'main'
            }
            steps {
                echo 'Creating release package'
                sh 'mkdir -p artifacts'
                sh 'cp ${SNAP_FILE} artifacts/'
                
                // Archive the snap package
                //archiveArtifacts artifacts: 'artifacts/*.snap', fingerprint: true
            }
        }
    }
    
    post {
        success {
            echo "Successfully built and tested auto-microk8s-cluster snap!"
        }
        failure {
            echo "Build or test failed, check the logs for details."
        }
        always {
            // Clean up Docker resources
            sh 'docker system prune -f || true'
        }
    }
}