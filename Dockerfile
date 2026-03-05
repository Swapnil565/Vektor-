FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY vektor/ ./vektor/
COPY pyproject.toml .
COPY README.md .

# Install package
RUN pip install --no-cache-dir .

# Default: show help
ENTRYPOINT ["vektor"]
CMD ["--help"]
