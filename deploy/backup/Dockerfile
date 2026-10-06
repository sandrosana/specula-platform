# syntax=docker/dockerfile:1
#
# Backup image (docs/architettura.md §15): pg_dump/pg_restore from the same
# PostgreSQL major version as the db service, plus age for encryption.

FROM postgres:16

RUN apt-get update \
    && apt-get install -y --no-install-recommends age \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 backup.sh restore-test.sh /usr/local/bin/

# Do not start a PostgreSQL server: this image only runs the backup scripts.
ENTRYPOINT []
CMD ["backup.sh", "schedule"]
