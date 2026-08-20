# The console, built and then served as static files.
#
# Two stages so the image that runs holds no toolchain: a Node build, and an
# nginx that only knows how to hand out what came out of it. The build stage is
# where pnpm and 300 megabytes of node_modules live and where they stay.

FROM node:24-alpine AS build

WORKDIR /src

# corepack ships with Node and reads packageManager from package.json, so the
# pnpm version is the one the lockfile was written with rather than whatever is
# newest today.
RUN corepack enable

# Dependencies first, and only the two files that decide them. Editing a
# component then rebuilds from here rather than from an install.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

FROM nginx:1.27-alpine AS runtime

# Angular writes to dist/<project>/browser. Copied by wildcard because the
# project name is the frontend's business, not this file's.
COPY --from=build /src/dist/*/browser /usr/share/nginx/html

COPY <<'EOF' /etc/nginx/conf.d/default.conf
server {
    listen 8080;
    root /usr/share/nginx/html;

    # A single-page application: every route the user can reach is index.html,
    # and the router sorts it out. Without this, refreshing on /inventory is a
    # 404 from nginx for a page that exists.
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Hashed filenames, so they can be cached hard. index.html cannot: it is
    # what points at the hashes, and a cached one serves last week's bundle.
    location ~* \.(js|css|woff2?|png|svg|ico)$ {
        # One header, not `expires 1y` as well: that directive emits a
        # Cache-Control of its own and the response goes out carrying two of
        # them, which is left to the client to reconcile.
        add_header Cache-Control "public, max-age=31536000, immutable";
    }

    location = /index.html {
        add_header Cache-Control "no-store";
    }
}
EOF
