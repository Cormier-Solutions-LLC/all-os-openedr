FROM docker.io/library/python:3.13-slim-trixie
WORKDIR /app
COPY LICENSE.md NOTICE.md /app/
COPY all_os_openedr /app/all_os_openedr
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-B", "-m", "all_os_openedr.manager"]
