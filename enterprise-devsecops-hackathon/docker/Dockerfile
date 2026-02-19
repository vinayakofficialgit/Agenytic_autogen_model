FROM openjdk:8-jdk-alpine

WORKDIR /app

ARG JAR_FILE=app/target/enterprise-app-1.0.jar
COPY ${JAR_FILE} app.jar

EXPOSE 8080
USER root

CMD ["java", "-jar", "app.jar"]