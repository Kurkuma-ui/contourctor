# ---------- Build stage ----------
FROM maven:3.9.9-eclipse-temurin-23 AS build
WORKDIR /app

# Копируем только pom.xml и качаем зависимости (кэшируется)
COPY pom.xml .
RUN mvn -q -B dependency:go-offline

# Теперь копируем исходники
COPY src ./src

# Сборка
RUN mvn -q -B package -DskipTests
# ---------- Runtime stage ----------
FROM eclipse-temurin:23-jre
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
