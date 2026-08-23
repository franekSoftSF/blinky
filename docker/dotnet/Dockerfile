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
# LDAP, for the directory the API reads people out of.
# System.DirectoryServices.Protocols is a thin wrapper over the platform's own
# client, and on Linux that client is a package rather than something shipped
# with the runtime. Without it the assembly loads and the first search throws
# about a missing library, which reads like a bug in this code.
#
# libgssapi_krb5 is separate, and unlike the two names above it is not
# optional. System.DirectoryServices.Protocols loads it when the interop
# initialises - whatever AuthType a connection asks for, including a simple
# bind that involves no Kerberos at all. Missing, every connection fails as
# "The LDAP server is unavailable" in about twenty milliseconds: a statement
# about reachability for a library that is not on disk. The real cause is
# printed once, on stderr, at process start -
#
#     Cannot load library libgssapi_krb5.so.2
#
# - and never again, so by the time anybody looks at a failing bind it has
# scrolled away, leaving a message that points at the network and at a
# directory answering perfectly.
#
# The package was renamed between Debian releases, so both names are tried and
# neither is fatal: an image without it still runs everything that is not the
# directory.
RUN apt-get update \
    && (apt-get install -y --no-install-recommends libldap-2.5-0 \
        || apt-get install -y --no-install-recommends libldap2 \
        || true) \
    && apt-get install -y --no-install-recommends libgssapi-krb5-2 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin blinky \
    && chown -R blinky /app
USER blinky
ENV BLINKY_ASSEMBLY=${ASSEMBLY}
ENTRYPOINT ["/bin/sh", "-c", "exec dotnet ${BLINKY_ASSEMBLY}.dll"]
