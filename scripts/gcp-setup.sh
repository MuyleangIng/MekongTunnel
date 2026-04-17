#!/bin/bash
# GCP Infrastructure Setup — mekongtunnel.dev
# Project: winter-sum-492801-q7
# Region:  asia-southeast1 (Singapore)

set -e

PROJECT="winter-sum-492801-q7"
REGION="asia-southeast1"
ZONE="asia-southeast1-b"

echo "==> Setting project..."
gcloud config set project $PROJECT

echo "==> Creating VMs..."

gcloud compute instances create tunnel-server \
  --machine-type=e2-small \
  --zone=$ZONE \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --boot-disk-size=20GB \
  --boot-disk-type=pd-ssd \
  --address=tunnel-ip \
  --tags=tunnel-server

gcloud compute instances create app-server \
  --machine-type=e2-standard-2 \
  --zone=$ZONE \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --boot-disk-size=30GB \
  --boot-disk-type=pd-ssd \
  --address=app-ip \
  --tags=app-server

echo "==> Creating firewall rules..."

# Tunnel server: port 22 for tunnel users, 2222 for admin SSH, 80+443 for web
gcloud compute firewall-rules create allow-tunnel-server \
  --allow=tcp:22,tcp:2222,tcp:80,tcp:443 \
  --target-tags=tunnel-server

# App server: port 22 for admin SSH, 80+443 for web (Postgres stays internal)
gcloud compute firewall-rules create allow-app-server \
  --allow=tcp:22,tcp:80,tcp:443 \
  --target-tags=app-server

echo ""
echo "==> Done! Your IPs:"
gcloud compute addresses list
echo ""
echo "==> Your VMs:"
gcloud compute instances list
