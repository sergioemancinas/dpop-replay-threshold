FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
# Tests are not skipped. XfccHeaderTests is self-contained and pins the exact parse
# behaviour that separates X1 from X2, so the image will not build if that behaviour
# changes.
RUN mvn -q -B package

FROM eclipse-temurin:21-jre@sha256:0b99b3376fbb50dbf9c0af8535fdd5b8eb0d3fdfc8b1e4967f383b6919f6901a
WORKDIR /app
COPY --from=build /build/target/xfcc-resource-server-1.0.0.jar app.jar
# Nothing here needs root.
USER 1000:1000
EXPOSE 8082
# Four of these run at once. Cap the heap so the set fits alongside Envoy on a
# shared integration host.
ENV JAVA_TOOL_OPTIONS="-Xmx192m -XX:MaxMetaspaceSize=192m"
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
