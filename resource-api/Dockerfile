FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5001
# 1 worker: as notas ficam em memória (didático), então o estado precisa ser único
CMD ["gunicorn", "-b", "0.0.0.0:5001", "-w", "1", "--threads", "4", "app:app"]