# Example taken from https://github.com/vulhub/vulhub/

FROM alpine:3.10

COPY . /app

EXPOSE 1099
EXPOSE 64000

CMD ["bash", "-c", "java -Djava.rmi.server.hostname=${RMIIP} -Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy=unlimited RemoteRMIServer"]
