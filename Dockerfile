# Build stage: compile the Go application
FROM golang:latest AS build

WORKDIR /app

# Copy the Go module files
COPY go.mod ./
COPY go.sum ./

# Download the Go module dependencies
RUN go mod download

COPY . .

# Build - TARGETARCH is automatically set by Docker Buildx for multi-arch builds
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o /engine-antiginx/App ./App
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o /engine-antiginx/Engined ./Engined

# Final stage: a minimal image to run the application
FROM alpine:latest AS run

WORKDIR /root/

# Copy the application executable from the build image
COPY --from=build /engine-antiginx/App /engine-antiginx/App
COPY --from=build /engine-antiginx/Engined /engine-antiginx/Engined

# Document the ports used by the applications
# App uses 8080, Engined uses 9090
EXPOSE 8080 9090
CMD ["/engine-antiginx/App"]
