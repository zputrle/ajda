FROM golang:1.25 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends libseccomp-dev && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 appuser

WORKDIR /app
RUN chown appuser:appuser /app

COPY --chown=appuser:appuser go.mod .
COPY --chown=appuser:appuser go.sum .
COPY --chown=appuser:appuser src/ ./src/
COPY --chown=appuser:appuser pages/ ./pages/

USER appuser

RUN go mod download
RUN go build -o ajda ./src/ajda.go

EXPOSE 8080

# Configuration for Fly.io.
CMD ["./ajda", "-rootDirPath", "./pages/", "--address", ":8080", "--home", "ajda.html", "--http_only", "--no_cgroups", "--no_landlock"]
