FROM maven:3.10-eclipse-temurin-21@sha256:d49bca545509b98965a808175862337dfdd24e1a8a4b11005cc8ce0578e52e8c AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B package -DskipTests

FROM eclipse-temurin:21-jre@sha256:ff92a063dac03a29fca3987bcfc66aa5f17769542df802bbf7d2ebaba4df8ebe
WORKDIR /app
COPY --from=build /build/target/d2-dpop-resource-server-1.0.0.jar app.jar
# Nothing here needs root.
USER 1000:1000
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
