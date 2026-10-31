FROM python:3.12-slim AS base
WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

FROM base AS testdeps
COPY requirements-dev.txt requirements-dev.lock ./
RUN pip install --no-cache-dir -r requirements-dev.lock

FROM testdeps AS lint
COPY . .
RUN ruff check .

FROM lint AS test
CMD ["python", "-m", "pytest", "-q"]

FROM base AS runtime
RUN apt-get update \
  && apt-get install -y --no-install-recommends gosu \
  && rm -rf /var/lib/apt/lists/*

# The published image is deliberately slim, so the ZFS userspace is opt-in
# (Mf-qirh): INSTALL_ZFS=1 builds the `-zfs` variant the ZFS snapshot provider
# needs, and the default stays the plain image every other deployment runs.
ARG INSTALL_ZFS=0

# `zfsutils-linux` lives in Debian's `contrib`, which the slim base does not
# enable, so a plain install answers "has no installation candidate". Both apt
# source layouts are handled -- the deb822 `debian.sources` of newer bases and
# the one-line `sources.list` of older ones -- and an already-enabled `contrib`
# is left alone, so the step is safe to re-run.
RUN if [ "$INSTALL_ZFS" = "1" ]; then \
      set -eu; \
      if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sources=/etc/apt/sources.list.d/debian.sources; \
        sed -i -E '/^Components:.*[[:space:]]contrib([[:space:]]|$)/!s/^Components:(.*)$/Components:\1 contrib/' "$sources"; \
      elif [ -f /etc/apt/sources.list ]; then \
        sources=/etc/apt/sources.list; \
        sed -i -E '/[[:space:]]contrib([[:space:]]|$)/!s/^(deb[[:space:]].*[[:space:]])main([[:space:]]|$)/\1main contrib\2/' "$sources"; \
      else \
        echo "INSTALL_ZFS=1: no Debian apt sources to enable contrib in" >&2; \
        exit 1; \
      fi; \
      if ! grep -qE '(^|[[:space:]])contrib([[:space:]]|$)' "$sources"; then \
        echo "INSTALL_ZFS=1: could not enable the contrib component in $sources" >&2; \
        exit 1; \
      fi; \
      apt-get update; \
      apt-get install -y --no-install-recommends zfsutils-linux; \
      rm -rf /var/lib/apt/lists/*; \
    fi

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

COPY . .
RUN mkdir -p /app/storage /app/data

EXPOSE 8000
ENTRYPOINT ["docker-entrypoint.sh"]
# uvicorn's access log records the full request line, query string included, and
# that now carries a short-lived signed file grant (M3-7bb7).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
