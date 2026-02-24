# Buildless runtime image: expects a prebuilt JAR in target/
FROM eclipse-temurin:17-jre

WORKDIR /app

# Copy the JAR that your pipeline built earlier
# (The docker build context must be `java-pilot-app/` so this path exists)
COPY java-pilot-app/target/java-pilot-app-1.0.0.jar /app/app.jar

# Optional: run as non-root (you can keep this commented for demo purposes)
# RUN adduser --system --uid 10001 appuser
# USER 10001

EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]


# # INTENTIONALLY risky base tag (non-pinned)
# FROM openjdk:17-jdk

# WORKDIR /app
# # Copies everything (could leak build files)
# COPY . /app

# # Build inside image (not ideal)
# RUN ./mvnw -q -DskipTests package || mvn -q -DskipTests package

# EXPOSE 8080
# CMD ["java","-jar","target/java-pilot-app-1.0.0.jar"]
