# FROM eclipse-temurin:17-jdk-alpine

# WORKDIR /app

# ARG JAR_FILE=enterprise-devsecops-hackathon/app/target/enterprise-app-1.0.jar
# COPY ${JAR_FILE} app.jar

# EXPOSE 8080

# USER root

# CMD ["java", "-jar", "app.jar"]

# FROM eclipse-temurin:17-jdk-alpine
# WORKDIR /app
# COPY enterprise-devsecops-hackathon/app/target/*.jar app.jar
# EXPOSE 8080
# ENTRYPOINT ["java","-jar","app.jar"]

FROM eclipse-temurin:17-jdk-alpine

# Security: run as non-root
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY enterprise-devsecops-hackathon/app/target/*.jar app.jar

EXPOSE 8080

# Container-aware JVM defaults
ENV JAVA_TOOL_OPTIONS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75 -XX:MinRAMPercentage=50 \
  -XX:+ExitOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError -XX:MaxMetaspaceSize=256m"

USER app
ENTRYPOINT ["java","-jar","/app/app.jar"]