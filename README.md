<div align="center">
  <img src="templates/static/favicon.png" width="100px" alt="logo" />
  <h1><code>mrinjamul auth</code></h1>
  <p>
    <strong>A asymmetric JWT based authentication service for user management.</strong>
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

Generate OpenAPI spec:

```bash
swag init --parseDependency --parseInternal
# swag init --parseDependency  --parseInternal -g main.go
```

To run the application, run the following commands:

```bash
export $(cat .env | xargs)
go build
./mrinjamul-auth
```

### Contributing

See the [contributing guide](CONTRIBUTING.md) for more information.

### License

- open sourced under the [MIT license](LICENSE)

Copyright (c) 2022 mrinjamul@gmail.com
