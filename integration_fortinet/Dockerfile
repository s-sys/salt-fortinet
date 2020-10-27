FROM python:3.7

WORKDIR /usr/src/app

RUN apt-get update -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y wget libaio1 alien

RUN wget -nv https://download.oracle.com/otn_software/linux/instantclient/19600/oracle-instantclient19.6-basic-19.6.0.0.0-1.x86_64.rpm && \
    alien --scripts -i oracle-instantclient19.6-basic-19.6.0.0.0-1.x86_64.rpm && \
    rm -f oracle-instantclient19.6-basic-19.6.0.0.0-1.x86_64.rpm && \
    echo /usr/lib/oracle/19.6/client64/lib/ > /etc/ld.so.conf.d/oracle.conf && \
    ldconfig

ENV ORACLE_HOME=/usr/lib/oracle/19.6/client64

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

STOPSIGNAL SIGINT
CMD [ "python3", "./integration_fortinet.py" ]
