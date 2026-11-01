# Local test fixture only. Build context: scripts/unseen_java/bookshop
#   docker build -t vajra-unseen-bookshop -f scripts/unseen_java/Dockerfile scripts/unseen_java/bookshop
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /src/target/bookshop-0.1.0.jar app.jar
RUN apt-get update -qq && apt-get install -y -qq iputils-ping >/dev/null && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /tmp/avatars && echo "avatar-bytes" > /tmp/avatars/default.png
# Inside the container it must bind 0.0.0.0 so the port can be published; publish to 127.0.0.1 only on the host.
ENV BIND_ADDR=0.0.0.0
EXPOSE 9400
CMD ["java", "-jar", "app.jar"]
