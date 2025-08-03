# Stage 1: Base image for runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Stage 2: Build image
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["ZenGChatApi.csproj", "."]
RUN dotnet restore "ZenGChatApi.csproj"
COPY . .
WORKDIR "/src"
RUN dotnet build "ZenGChatApi.csproj" -c Release -o /app/build

# Stage 3: Publish image
FROM build AS publish
RUN dotnet publish "ZenGChatApi.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 4: Final image
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "ZenGChatApi.dll"]