---

# Injective Publishing Node

This repository is a fork of [InjectiveLabs/injective-core](https://github.com/InjectiveLabs/injective-core), specifically enhanced to include functionality for NATS publishing. It allows the `injectived` node to publish data streams of transactions, mempool, blocks, and proposed blocks.

## Added Functionality

- **NATS Publishing**: Enhances the `injectived` node to publish details about transactions, mempool, blocks, and proposed blocks via NATS. This feature enables subscribers to receive real-time blockchain data.

- **How to Use**: To enable the publishing features, you must set the following environment variables before starting the `injectived` node. These variables configure the NATS connection and define the publishing settings:

    - **NATS URL**  
      `NATS_URL=your-nats-url`

    - **NATS NKey**  
      `NATS_NKEY=your-nats-nkey`

    - **NATS JWT**  
      `NATS_JWT=your-nats-jwt`

    - **Publisher Prefix**  
      `PUB_PREFIX=your-publisher-prefix`

    - **Publisher Name**  
      `PUB_NAME=your-publisher-name`

  You can use these environment variables in the `injectived` or `cosmovisor` service file. For example:
    ```
    [Unit]
    Description=Injectived Service
    After=network.target

    [Service]
    User=injective
    Type=simple
    Restart=on-failure
    RestartSec=5s
    Environment="NATS_URL=your-nats-url"
    Environment="NATS_NKEY=your-nats-nkey"
    Environment="NATS_JWT=your-nats-jwt"
    Environment="PUB_PREFIX=your-publisher-prefix"
    Environment="PUB_NAME=your-publisher-name"
    Environment="LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/"
    Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/home/injective/go/bin"
    ExecStart=/home/injective/injectived start

    [Install]
    WantedBy=multi-user.target
    ```

#### To improve node performance and save space, configure the following settings in your `app.toml` and `config.toml` files:

**app.toml**:
```toml
# Prune Type
pruning = "custom"

# Prune Strategy
pruning-keep-recent = "100"
pruning-keep-every = "0"
pruning-interval = "10"
```

**config.toml**:
```toml
indexer = "null"
peer_gossip_sleep_duration = "2ms"
persistent_peers = "" # load all peers from https://polkachu.com/live_peers/injective
max_num_outbound_peers = 100
```

---

# Injective-Core [![codecov](https://codecov.io/gh/InjectiveLabs/injective-core/branch/dev/graph/badge.svg?token=WTDFT58GB8)](https://codecov.io/gh/InjectiveLabs/injective-core)

![Banner!](assets/logo.png)

[//]: # ([![Project Status: Active -- The project has reached a stable, usable)
[//]: # (state and is being actively)
[//]: # (developed.]&#40;https://img.shields.io/badge/repo%20status-Active-green.svg?style=flat-square&#41;]&#40;https://www.repostatus.org/#active&#41;)
[//]: # ([![GoDoc]&#40;https://img.shields.io/badge/godoc-reference-blue?style=flat-square&logo=go&#41;]&#40;https://pkg.go.dev/github.com/InjectiveLabs/sdk-go/chain&#41;)
[//]: # ([![Discord]&#40;https://badgen.net/badge/icon/discord?icon=discord&label&#41;]&#40;https://discord.gg/injective&#41;)


Home of the following services:

* [injectived](/cmd/injectived)

## Architecture

<img alt="architecture.png" src="./assets/architecture.png" width="100%"/>

## Installation

### Building from sources

In order to build from source you’ll need at least [Go 1.16+](https://golang.org/dl/).

```bash
# need to clone if you plan to run tests, and use Makefile
$ git clone git@github.com:InjectiveLabs/injective-core.git
$ cd injective-core
$ make install

# or simply do this to fetch modules and build executables
$ go install github.com/InjectiveLabs/injective-core/cmd/...
```

### Quick Setup
The most convenient way to launch services is by running the setup script:
```bash
$ ./setup.sh
```
Then run an instance of the injectived node.
```bash
$ ./injectived.sh
```

Voila! You have now successfully setup a full node on the Injective Chain.

## Generating REST and gRPC Gateway docs
First, ensure that the `Enable` and `Swagger` values are true in APIConfig set in `cmd/injectived/config/config.go`.

Then simply run the following command to auto-generate the Swagger UI docs.
```bash
$ make proto-swagger-gen
```
Then when you start the Injective Daemon, simply navigate to [http://localhost:10337/swagger/](http://localhost:10337/swagger/).

## Generating Injective Chain API gRPC Typescript bindings

```bash
$ make gen
```
Then when you start the Injective Daemon, simply navigate to [http://localhost:10337/swagger/](http://localhost:10337/swagger/).


## Maintenance

To run all unit tests:

```bash
$ go test ./injective-chain/...
```
