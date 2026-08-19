# One Dockerfile for both containerised services. The Windows-only projects
# (Agent.Ui, AdcsConnector) are never in the graph of these two, so nothing in
# the solution has to be excluded by hand.
ARG DOTNET_VERSION=10.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
ARG PROJECT
WORKDIR /src
COPY . .
RUN dotnet publish "${PROJECT}" -c Release -o /app --no-self-contained

FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS final
ARG ASSEMBLY
WORKDIR /app
COPY --from=build /app .
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin blinky \
    && chown -R blinky /app
USER blinky
ENV BLINKY_ASSEMBLY=${ASSEMBLY}
ENTRYPOINT ["/bin/sh", "-c", "exec dotnet ${BLINKY_ASSEMBLY}.dll"]
