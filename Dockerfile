# Use an official Jetty base image with Java 17
FROM jetty:jdk17

# Set environment variables for Jetty/Application
ENV JETTY_BASE /var/lib/jetty
ENV JETTY_HOME /usr/local/jetty
ENV JETTY_RUN /tmp/jetty

RUN java -jar "$JETTY_HOME/start.jar" --add-modules=http,jdbc,jndi,ee10-deploy

# Pre-seed the local_fs storage mount point owned by the jetty user (§5.1):
# a named Docker volume takes its initial ownership from the image directory
# it's mounted onto, so this must happen before the volume is first created.
# The base image's default user (jetty, non-root) can't create a dir under
# /, so switch to root for this step only.
USER root
RUN mkdir -p /data/tsi-sign/documents && chown -R jetty:jetty /data/tsi-sign

# Local PKI evaluation keystore (§7, §10.6): a self-signed dev keypair under
# alias "tsi_corporate_seal" so a fresh self-hosted deployment can seal
# documents immediately with zero setup. Real deployments should replace
# this with an org-issued cert (KEYSTORE_PATH/KEYSTORE_PASSWORD env vars) —
# the admin console gets an upload/rotate workflow for this in Chunk 11.
RUN mkdir -p /etc/tsi-sign && \
    keytool -genkeypair \
        -alias tsi_corporate_seal \
        -keyalg RSA -keysize 2048 -validity 3650 \
        -dname "CN=TSI Sign Local Dev, OU=TSI Coop, O=TSI Coop, L=Coimbatore, ST=TN, C=IN" \
        -keystore /etc/tsi-sign/keystore.p12 -storetype PKCS12 \
        -storepass changeit -keypass changeit && \
    chown -R jetty:jetty /etc/tsi-sign

USER jetty

# Copy the built WAR file into Jetty's webapps directory
COPY target/tsi_sign.war ${JETTY_BASE}/webapps/root.war

EXPOSE 8080
