# TSI eSign Sandbox - a mock CCA-licensed eSign Service Provider + CA. NOT for production.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:17-jre
RUN useradd --system --create-home sandbox && mkdir -p /data/ca && chown sandbox:sandbox /data/ca
COPY --from=build /build/target/tsi_esign_sandbox.jar /app/sandbox.jar
USER sandbox
EXPOSE 8090
CMD ["java", "-jar", "/app/sandbox.jar"]
