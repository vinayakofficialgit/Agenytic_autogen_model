FROM openjdk:8-jdk-alpine

WORKDIR /app
COPY ../app/target/enterprise-app-1.0.jar app.jar

EXPOSE 8080
USER root

CMD ["java", "-jar", "app.jar"]