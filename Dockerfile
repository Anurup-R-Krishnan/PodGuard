FROM python:3.11-slim

LABEL maintainer="EPSS Framework"
LABEL description="EPSS-Augmented CVE Prioritization Framework"

# Install Trivy
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget apt-transport-https gnupg lsb-release ca-certificates && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | tee /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends trivy && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project
COPY pyproject.toml README.md ./
COPY epss_framework/ ./epss_framework/

# Install Python dependencies
RUN pip install --no-cache-dir -e ".[all]"

# Create reports directory
RUN mkdir -p /app/epss-reports

# Default entrypoint
ENTRYPOINT ["epss-triage"]
CMD ["--help"]
