/* Requires the Docker Pipeline plugin */
/* Modified for test purpose */
pipeline {
    agent { docker { image 'python:3.12.6-alpine3.20' } }
    stages {
        stage('build') {
            steps {
                sh 'python --version'
            }
        }
    }
}
