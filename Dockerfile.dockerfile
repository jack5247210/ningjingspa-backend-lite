# 階段一：使用 Gradle 映像檔來編譯
FROM gradle:jdk21 AS build
WORKDIR /app
COPY . .
# 跳過測試加速編譯
RUN ./gradlew build -x test

# 階段二：使用輕量級 JDK 映像檔來執行
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
# 把剛剛編譯好的 jar 檔複製過來
COPY --from=build /app/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]