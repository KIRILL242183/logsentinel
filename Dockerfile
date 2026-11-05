FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY logsentinel ./logsentinel
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 sentinel
USER sentinel
ENTRYPOINT ["logsentinel"]
CMD ["--help"]
