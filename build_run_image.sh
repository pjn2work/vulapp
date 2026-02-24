docker build -t vulweb .
docker run -d -p 5000:5000 --name vulweb-container vulweb
