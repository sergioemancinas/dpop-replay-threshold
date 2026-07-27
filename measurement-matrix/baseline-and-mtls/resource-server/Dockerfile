FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /build/target/mtls-resource-server-1.0.0.jar app.jar
# Nothing here needs root.
USER 1000:1000
EXPOSE 8444
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
