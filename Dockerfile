# syntax=docker/dockerfile:1

# ---- Stage 1: build the jar with the Maven wrapper (JDK, build tools) ----
FROM eclipse-temurin:24.0.2_12-jdk-alpine AS build
WORKDIR /workspace

COPY mvnw pom.xml ./
COPY .mvn/ .mvn/
COPY src/ src/

# Tests run in the CI pipeline; the cache mount keeps ~/.m2 out of the image
RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw -B -q package -DskipTests \
    && cp target/omar-petclinic-*.jar /workspace/app.jar

# ---- Stage 2: minimal runtime (JRE only, no compiler, no Maven, no sources) ----
FROM eclipse-temurin:24.0.2_12-jre-alpine

# Dedicated unprivileged user with a fixed UID/GID
RUN addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app -s /sbin/nologin app

WORKDIR /app

# Owned by root and read-only for the app user: the process cannot modify its own binary
COPY --from=build /workspace/app.jar /app/app.jar

USER 10001:10001

ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -Djava.io.tmpdir=/tmp"

EXPOSE 9966

# busybox wget ships with Alpine; no extra package needed
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:9966/petclinic/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
