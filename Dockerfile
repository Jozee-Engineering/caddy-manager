FROM python:3.12-slim
WORKDIR /app
COPY app/ /app/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).status==200 else 1)"
CMD ["python", "-u", "server.py"]
