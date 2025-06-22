# Building and Publishing the Pre-Populated VaultWarden Image

## 1. Copy the Populated Database

Copy the backup database to the Docker build context:

```sh
cp /var/lib/docker/volumes/org_invite_vaultwarden_data/_data/db-backup.sqlite3 ./docker/db.sqlite3
```

## 2. Build the Docker Image

Replace `<your-dockerhub-username>` with your Docker Hub username:

```sh
docker build -t <your-dockerhub-username>/vaultwarden-dev-populated:latest -f docker/Dockerfile.vw-populated ./docker
```

## 3. Push to Docker Hub

```sh
docker login
# Then push the image

docker push <your-dockerhub-username>/vaultwarden-dev-populated:latest
```

## 4. Use in Docker Compose or CI

In your compose or CI files, use:

```yaml
image: <your-dockerhub-username>/vaultwarden-dev-populated:latest
```

## Notes
- This image will always start with your pre-populated user, organisation, and secrets.
- To update the image for a new VaultWarden version or new data, repeat the backup and build steps.
