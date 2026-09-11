# jailhub container (DESIGN.md §14 M4). Builds the native binary with GraalVM, ships it on a
# distroless base: no JVM, no shell, ~30 MB image.
#
#   docker build -f deploy/Dockerfile -t jailhub .
#   docker run -d --name jailhub -p 443:443 -p 80:80 -p 53:53/udp -p 53:53/tcp -p 10000-10999:10000-10999 \
#       -v jailhub-state:/var/lib/jailhub jailhub serve --base-url https://hub.example.com --acme-email ops@example.com
#
# The state volume holds hub.key, tls/ and the event log: back it up, it is the whole hub.

FROM ghcr.io/graalvm/native-image-community:25 AS build
WORKDIR /src
COPY . .
RUN ./mvnw -B -ntp -DskipTests -Pnative -pl hub -am package

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/hub/target/jailhub /jailhub
ENV JAILHUB_STATE=/var/lib/jailhub
VOLUME /var/lib/jailhub
EXPOSE 443 80 53/udp 53/tcp 10000-10999
USER nonroot
ENTRYPOINT ["/jailhub"]
CMD ["serve", "--help"]
