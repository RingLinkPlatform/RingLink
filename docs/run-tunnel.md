# Run a simple tunnel based on RingLink

This guide will show you how to run a simple tunnel based on RingLink.

## Prerequisites

* Two hosts with Linux, at least one of them should have a public IP address.
* Rust toolchain (optional)

## Steps

The following steps will guide you through setting up a simple tunnel between two hosts.

### 1. Build tunnel examples (optional)

Build the tunnel examples with the following command or download the pre-built binaries

```shell
cargo build --example tunnel
```

You can find the built binaries in the `target/debug/examples` directory.

### 2. Generate a key pair

Generate a key pair for the tunnel on both hosts.

Run the following command on both hosts:

```shell
tunnel identity generate
```

By default, the key pair will be saved in the `identity.secret` in the current directory.

Public key will be printed to the console. You should see output similar to the following:

```text
generating a new identity
identity generated!
client id: fefe13799f
client public key: OWMJULxNwXKAlk6zTRwPsxJnCBNXxG7BPC1bKuVUF4s=
saving identity to identity.secret
```

If you want to retrieve the public key later, you can run the following command:

```shell
tunnel identity print
```

### 3. Prepare network config

First, generate a new network id with the following command:

```shell
tunnel network generate-id
```

Then, create a config file `config.toml` with the following content on **both hosts**:

```toml
listen = "0.0.0.0:42567"
identity_file = "identity.secret"

[network]
id = "794d5c99"
mtu = 1350
```

Choose an IP address for each host, for example:

* Host A: `192.168.88.1/24`
* Host B: `192.168.88.2/24`

Add IP addresses to the `config.toml` network section, your config file should look like this:

On **Host A**:

```toml
listen = "0.0.0.0:42567"
identity_file = "identity.secret"

[network]
id = "794d5c99"
mtu = 1350
ip = "192.168.88.1/24"
```

On **Host B**:

```toml
[network]
id = "794d5c99"
mtu = 1350
ip = "192.168.88.2/24"
```

### 4. Add peers config

Add the peer's public key and ip to the `config.toml` file on **both hosts**.

For example, on **Host A**, add the following to the `config.toml` file:

**Note**: replace the public key and encryption key with the ones generated in step 2 on **Host B**

```toml
[[peers]]
public_key = "Dec0kFD1TxfnQ0iSl/+xpqWeeWGRznnyPgWCKeb4hX0="
endpoint = "1.1.1.1:42567"
```

On **Host B**, add Host A's public key and encryption key like this:

```toml
[[peers]]
public_key = "zIMMxyzJH1tnwhdOZJRlUPlwREyR2ZYgNkpHtxyErhA="
endpoint = "2.2.2.2:42567"
```

### 5. Check config

Now you should have a `config.toml` file on both hosts. Check the config file to make sure it's correct.

The full config file should look like this:

```toml
listen = "0.0.0.0:42567"
identity_file = "identity.secret"

[[peers]]
public_key = "zIMMxyzJH1tnwhdOZJRlUPlwREyR2ZYgNkpHtxyErhA="
endpoint = "2.2.2.2:42567"

[network]
id = "794d5c99"
mtu = 1350
ip = "192.168.88.2/24"
```

### 6. Run tunnel

On both hosts, run the following command:

```shell
tunnel run --config config.toml
```

### 7. Check tunnel is running

Open a new terminal and run the following command on both hosts:

```shell
ip a show
```

You should see a new network interface named with your network id with the IP address you configured in the
`config.toml` file.

Ping the other host to check if the tunnel is working:

For example, on **Host A**:

```shell
ping 192.168.88.2
```
