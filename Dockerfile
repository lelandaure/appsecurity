FROM golang:1.19-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
COPY . ./

RUN ls

RUN go build -o /appsecurity

EXPOSE 8080

CMD [ "/appsecurity" ]