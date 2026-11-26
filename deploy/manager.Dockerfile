FROM docker.io/library/python:3.13-slim-trixie@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50
WORKDIR /app
COPY LICENSE.md NOTICE.md /app/
COPY all_os_openedr /app/all_os_openedr
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-B", "-m", "all_os_openedr.manager"]
