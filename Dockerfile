FROM python:3.12-slim
WORKDIR /srv
RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ flask gunicorn
COPY app/ /srv/
RUN useradd -u 10001 -m appuser && mkdir -p /data/files && chown -R appuser /data /srv
USER appuser
ENV DATA_DIR=/data
EXPOSE 8000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "--timeout", "65", "wsgi:app"]
