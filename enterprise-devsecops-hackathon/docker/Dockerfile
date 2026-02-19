# FROM eclipse-temurin:17-jdk-alpine

# WORKDIR /app

# ARG JAR_FILE=enterprise-devsecops-hackathon/app/target/enterprise-app-1.0.jar
# COPY ${JAR_FILE} app.jar

# EXPOSE 8080

# USER root

# CMD ["java", "-jar", "app.jar"]

FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY enterprise-devsecops-hackathon/app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","app.jar"]