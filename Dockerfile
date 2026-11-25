# 面板镜像(内含节点端二进制,供一键对接脚本下载)
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/kaze-panel ./cmd/kaze-panel \
 && for a in amd64 arm64; do CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -ldflags "-s -w" -o /out/dist/kaze-node-linux-$a ./cmd/kaze-node; done

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/kaze-panel /kaze-panel
COPY --from=build /out/dist /dist
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/kaze-panel", "-listen", ":8080", "-data", "/data", "-dist", "/dist"]
