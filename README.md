<div align="center">
  <h1><code>mrinjamul auth</code></h1>
  <p>
    <strong>Authentication service for mrinjamul</strong>
  </p>
</div>

### Requirements

- [Golang](https://golang.org/dl/)
- [Docker](https://docs.docker.com/get-docker/) (Optional but recommended)
- [Postgresql](https://www.postgresql.org/download/) (**Only if you are not using `docker`**)

### Development

To get started, you can clone the repository and run the following commands:

```bash
git clone https://github.com/mrinjamul/mrinjamul-auth.git
```

To install the dependencies, run the following commands:

```bash
cd mrinjamul-auth
go mod download
```

Copy environment variables file and replace the values with your own.

```bash
cp .env.example .env
```

To run the application, run the following commands:

```bash
export $(cat .env | xargs)
go build
./mrinjamul-auth
```

### License

- No License currently. All rights reserved to the original author.

Copyright (c) 2022 mrinjamul@gmail.com
