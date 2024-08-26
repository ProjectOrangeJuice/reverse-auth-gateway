FROM scratch

COPY web/src web/src/
COPY gateway gateway

ENTRYPOINT ["./gateway"]