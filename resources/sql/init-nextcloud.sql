CREATE USER nextclouddb;
CREATE DATABASE nextclouddb;
GRANT ALL PRIVILEGES ON DATABASE nextclouddb TO nextclouddb;
ALTER USER nextclouddb PASSWORD 'betatester';
