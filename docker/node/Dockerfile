FROM openjdk:8-jdk-alpine

RUN adduser -S -h /var/lib/constellation constellation

COPY cl-node.jar /var/lib/constellation/cl-node.jar
COPY logback.xml /var/lib/constellation/logback.xml

WORKDIR /var/lib/constellation/

ENV ip "127.0.0.1"
ENV xmx 5G
ENV CL_KEYSTORE_NAME ""
ENV CL_ALIAS ""
ENV CL_STOREPASS ""
ENV CL_KEYPASS ""

USER constellation

EXPOSE 9000
EXPOSE 9001

ENTRYPOINT java -Dlogback.configurationFile=/var/lib/constellation/logback.xml -Xmx$xmx -XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap -jar cl-node.jar --ip $ip --port 9000 -k $CL_KEYSTORE_NAME --alias $CL_ALIAS
