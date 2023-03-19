FROM python:slim

RUN useradd certificates

WORKDIR /home/certificates

COPY requirements.txt requirements.txt
RUN python -m venv venv
RUN venv/bin/pip install -r requirements.txt
RUN venv/bin/pip install gunicorn

COPY app app
COPY migrations migrations
COPY cert.py config.py boot.sh ./
RUN chmod +x boot.sh

ENV FLASK_APP cert.py

RUN chown -R certificates:certificates ./
USER certificates

EXPOSE 5000
ENTRYPOINT ["./boot.sh"]
