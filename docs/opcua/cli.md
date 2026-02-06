# edgeo-opcua - OPC UA Command Line Interface

A command-line tool for interacting with OPC UA servers.

## Installation

```bash
go build -o edgeo-opcua ./cmd/edgeo-opcua
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `browse` | Browse the OPC UA address space |
| `read` | Read values from OPC UA nodes |
| `write` | Write values to OPC UA nodes |
| `subscribe` | Subscribe to data changes on nodes |
| `discovery` | Discover OPC UA servers and endpoints |
| `gencert` | Generate a self-signed client certificate |
| `version` | Print version information |

## Global Flags

### Connection

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--endpoint` | `-e` | `opc.tcp://localhost:4840` | OPC UA server endpoint URL |
| `--timeout` | `-t` | `5000` | Operation timeout in milliseconds |
| `--verbose` | `-v` | `false` | Enable verbose output |

### Security

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--security-policy` | `-s` | `None` | Security policy |
| `--security-mode` | `-m` | `None` | Security mode |
| `--cert` | | | Path to client certificate file (PEM format) |
| `--key` | | | Path to client private key file (PEM format) |

### Security Policies

| Policy | Description |
|--------|-------------|
| `None` | No security (default) |
| `Basic128Rsa15` | Basic 128-bit RSA 1.5 (deprecated) |
| `Basic256` | Basic 256-bit (deprecated) |
| `Basic256Sha256` | Basic 256-bit with SHA-256 |
| `Aes128Sha256RsaOaep` | AES 128-bit with SHA-256 and RSA-OAEP |
| `Aes256Sha256RsaPss` | AES 256-bit with SHA-256 and RSA-PSS |

### Security Modes

| Mode | Description |
|------|-------------|
| `None` | No security (default) |
| `Sign` | Messages are signed |
| `SignAndEncrypt` | Messages are signed and encrypted |

:::note
When using a security mode other than `None`, you must provide both `--cert` and `--key` flags, and the security policy must also be set to something other than `None`.
:::

## Node ID Format

OPC UA Node IDs follow the standard format:

| Format | Example | Description |
|--------|---------|-------------|
| `ns=<N>;i=<ID>` | `ns=2;i=1` | Numeric node ID in namespace N |
| `ns=<N>;s=<Name>` | `ns=2;s=Temperature` | String node ID in namespace N |
| `i=<ID>` | `i=84` | Numeric node ID in namespace 0 |
| `s=<Name>` | `s=MyNode` | String node ID in namespace 0 |

Well-known node IDs:

| Node ID | Description |
|---------|-------------|
| `i=84` | Root node |
| `i=85` | Objects folder |
| `i=86` | Types folder |
| `i=87` | Views folder |
| `i=2253` | Server node |

## Command: browse

Browse nodes in the OPC UA server address space.

### Usage

```bash
edgeo-opcua browse [flags]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--node` | `-n` | `i=84` | Node ID to browse from (default: Root) |
| `--direction` | `-d` | `forward` | Browse direction: forward, inverse, both |
| `--depth` | | `1` | Browse depth (1 = immediate children only) |

### Examples

```bash
# Browse from root node
edgeo-opcua browse -e opc.tcp://localhost:4840

# Browse the Objects folder
edgeo-opcua browse -e opc.tcp://localhost:4840 -n "i=85"

# Browse a specific node with forward references
edgeo-opcua browse -e opc.tcp://localhost:4840 -n "ns=2;s=MyNode" -d forward

# Browse with inverse references
edgeo-opcua browse -e opc.tcp://localhost:4840 -n "ns=2;i=1" -d inverse

# Browse all references (forward and inverse)
edgeo-opcua browse -e opc.tcp://localhost:4840 -n "i=85" -d both
```

**Sample output:**

```
Browsing from: i=85
Direction: forward
Found 4 references:

[1] Server
    NodeID:    i=2253
    NodeClass: Object
    BrowseName: Server

[2] DeviceSet
    NodeID:    ns=2;i=1
    NodeClass: Object
    BrowseName: DeviceSet

[3] Temperature
    NodeID:    ns=2;s=Temperature
    NodeClass: Variable
    BrowseName: Temperature
    TypeDef:   i=63

[4] Pressure
    NodeID:    ns=2;s=Pressure
    NodeClass: Variable
    BrowseName: Pressure
    TypeDef:   i=63
```

## Command: read

Read attribute values from one or more OPC UA nodes.

### Usage

```bash
edgeo-opcua read [flags]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--node` | `-n` | | Node ID(s) to read (required, can specify multiple) |
| `--attribute` | `-a` | `Value` | Attribute to read |

### Supported Attributes

| Attribute | Description |
|-----------|-------------|
| `NodeId` | Node identifier |
| `NodeClass` | Node class (Object, Variable, Method, etc.) |
| `BrowseName` | Browse name of the node |
| `DisplayName` | Display name of the node |
| `Description` | Description of the node |
| `Value` | Current value (default) |
| `DataType` | Data type of the value |
| `ValueRank` | Value rank (scalar, array, etc.) |
| `ArrayDimensions` | Array dimensions |
| `AccessLevel` | Access level flags |

### Examples

```bash
# Read a single node value
edgeo-opcua read -e opc.tcp://localhost:4840 -n "ns=2;i=1"

# Read a string-based node ID
edgeo-opcua read -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" -a Value

# Read multiple nodes at once
edgeo-opcua read -e opc.tcp://localhost:4840 -n "i=2253" -n "i=2254"

# Read the display name of a node
edgeo-opcua read -e opc.tcp://localhost:4840 -n "ns=2;i=1" -a DisplayName

# Read the data type of a node
edgeo-opcua read -e opc.tcp://localhost:4840 -n "ns=2;i=1" -a DataType
```

**Sample output:**

```
Node: ns=2;s=Temperature
  Attribute: Value
  Value: 25.5
  Type: Double
  SourceTimestamp: 2026-02-05T14:30:00.000Z
  ServerTimestamp: 2026-02-05T14:30:00.001Z
  Status: Good
```

## Command: write

Write values to OPC UA nodes.

### Usage

```bash
edgeo-opcua write [flags]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--node` | `-n` | | Node ID to write to (required) |
| `--value` | | | Value to write (required) |
| `--type` | `-T` | `auto` | Value type |

### Value Types

| Type | Aliases | Description |
|------|---------|-------------|
| `auto` | | Automatically detect type (default) |
| `bool` | `boolean` | Boolean value |
| `int16` | | Signed 16-bit integer |
| `uint16` | | Unsigned 16-bit integer |
| `int32` | `int` | Signed 32-bit integer |
| `uint32` | `uint` | Unsigned 32-bit integer |
| `int64` | | Signed 64-bit integer |
| `uint64` | | Unsigned 64-bit integer |
| `float` | `float32` | 32-bit floating point |
| `double` | `float64` | 64-bit floating point |
| `string` | | String value |

Auto-detection rules:
- `true` / `false` are detected as `bool`
- Integer-parseable values are detected as `int64`
- Decimal values are detected as `double`
- All other values are detected as `string`

### Examples

```bash
# Write with auto type detection
edgeo-opcua write -e opc.tcp://localhost:4840 -n "ns=2;i=1" --value 42

# Write a double value
edgeo-opcua write -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" --value 25.5 -T double

# Write a string value
edgeo-opcua write -e opc.tcp://localhost:4840 -n "i=1234" --value "Hello World" -T string

# Write a boolean value
edgeo-opcua write -e opc.tcp://localhost:4840 -n "ns=2;i=5" --value true -T bool

# Write a float value
edgeo-opcua write -e opc.tcp://localhost:4840 -n "ns=2;i=10" --value 3.14 -T float
```

**Sample output:**

```
Successfully wrote value to ns=2;s=Temperature
  Value: 25.5
  Type: Double
```

## Command: subscribe

Subscribe to data changes on OPC UA nodes and print updates in real time.

### Usage

```bash
edgeo-opcua subscribe [flags]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--node` | `-n` | | Node ID(s) to subscribe to (required, can specify multiple) |
| `--interval` | `-i` | `1000` | Publishing interval in milliseconds |
| `--sample` | | `250` | Sampling interval in milliseconds |

### Examples

```bash
# Subscribe to a single node
edgeo-opcua subscribe -e opc.tcp://localhost:4840 -n "ns=2;i=1"

# Subscribe with custom publishing interval
edgeo-opcua subscribe -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" -i 1000

# Subscribe to multiple nodes
edgeo-opcua subscribe -e opc.tcp://localhost:4840 -n "i=2253" -n "i=2254" --sample 250

# Subscribe with faster sampling
edgeo-opcua subscribe -e opc.tcp://localhost:4840 -n "ns=2;i=1" -i 500 --sample 100
```

**Sample output:**

```
Subscription created (ID: 1, Interval: 1000ms)
Monitoring 2 nodes:
  [1] ns=2;s=Temperature (ID: 1, Interval: 250ms)
  [2] ns=2;s=Pressure (ID: 2, Interval: 250ms)

Waiting for data changes (Ctrl+C to stop)...

[14:30:01.123] ns=2;s=Temperature = 25.5
[14:30:01.124] ns=2;s=Pressure = 101.3
[14:30:02.125] ns=2;s=Temperature = 25.7
[14:30:03.126] ns=2;s=Temperature = 25.6
[14:30:03.127] ns=2;s=Pressure = 101.2
```

Press `Ctrl+C` to stop the subscription.

## Command: discovery

Discover available OPC UA servers and their endpoints.

### Usage

```bash
edgeo-opcua discovery [flags]
```

The `discovery` command uses the global `--endpoint` flag to specify the server to query. It automatically tries multiple discovery URL patterns (including `/discovery` and `/Discovery` suffixes) if the initial connection fails.

### Examples

```bash
# Discover endpoints on local server
edgeo-opcua discovery -e opc.tcp://localhost:4840

# Discover endpoints on remote server
edgeo-opcua discovery -e opc.tcp://opcuaserver.com:48010

# Discover with verbose output showing all attempts
edgeo-opcua discovery -e opc.tcp://10.0.0.50:4840 -v
```

**Sample output:**

```
OPC UA Discovery Results
========================

Discovery URL: opc.tcp://localhost:4840

Server Information:
  Application URI:  urn:mycompany:myserver
  Product URI:      urn:mycompany:myproduct
  Application Name: My OPC UA Server
  Application Type: Server
  Discovery URLs:
    - opc.tcp://localhost:4840

Available Endpoints (3):
-----------------------

[1] opc.tcp://localhost:4840
    Security Policy: None
    Security Mode:   None
    Security Level:  0
    Transport:       http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary
    Authentication:
      - anonymous (Anonymous)
      - username (UserName)

[2] opc.tcp://localhost:4840
    Security Policy: Basic256Sha256
    Security Mode:   Sign
    Security Level:  1
    Transport:       http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary
    Authentication:
      - username (UserName, requires Basic256Sha256)
    Certificate:     Present (1024 bytes)

[3] opc.tcp://localhost:4840
    Security Policy: Basic256Sha256
    Security Mode:   SignAndEncrypt
    Security Level:  2
    Transport:       http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary
    Authentication:
      - username (UserName, requires Basic256Sha256)
    Certificate:     Present (1024 bytes)

Summary:
--------
  Server supports unsecured connections (SecurityPolicyNone)
  Server supports Sign mode
  Server supports SignAndEncrypt mode

Connection Examples:
--------------------
  Unsecured: edgeo-opcua browse -e opc.tcp://localhost:4840
  Secured:   edgeo-opcua browse -e opc.tcp://localhost:4840 --security-policy Basic256Sha256 --security-mode SignAndEncrypt
```

## Command: gencert

Generate a self-signed X.509 certificate and private key for OPC UA client authentication.

### Usage

```bash
edgeo-opcua gencert [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--cert` | `client-cert.pem` | Output path for certificate |
| `--key` | `client-key.pem` | Output path for private key |
| `--org` | `OPC UA Client` | Organization name |
| `--country` | `US` | Country code (2 letters) |
| `--locality` | | Locality/City name |
| `--app-uri` | `urn:opcua:client:app` | OPC UA Application URI |
| `--dns` | | Comma-separated DNS names |
| `--ip` | | Comma-separated IP addresses |
| `--days` | `365` | Certificate validity in days |
| `--key-size` | `2048` | RSA key size in bits (2048 or 4096) |

### Certificate Details

The generated certificate includes extensions required for OPC UA:

- **Subject Alternative Name** with the Application URI
- **Key Usage**: Digital Signature, Key Encipherment, Data Encipherment
- **Extended Key Usage**: Client Authentication
- **DNS Names**: `localhost` by default, or as specified with `--dns`
- **IP Addresses**: `127.0.0.1` by default, or as specified with `--ip`

### Examples

```bash
# Generate certificate with defaults
edgeo-opcua gencert

# Generate certificate with custom output paths
edgeo-opcua gencert --cert ./my-cert.pem --key ./my-key.pem

# Generate certificate with custom application URI
edgeo-opcua gencert --app-uri "urn:mycompany:myapp:client"

# Generate certificate valid for specific hostnames and IPs
edgeo-opcua gencert --dns "localhost,myhost.local" --ip "127.0.0.1,192.168.1.100"

# Generate certificate with 4096-bit key valid for 2 years
edgeo-opcua gencert --key-size 4096 --days 730

# Generate and immediately use for a secured connection
edgeo-opcua gencert --cert client.pem --key client-key.pem
edgeo-opcua browse -e opc.tcp://server:4840 -s Basic256Sha256 -m SignAndEncrypt --cert client.pem --key client-key.pem
```

**Sample output:**

```
Generating 2048-bit RSA key pair...
Creating self-signed certificate...

Certificate generated successfully!

Certificate: client-cert.pem
Private Key: client-key.pem

Certificate Details:
  Subject:         CN=OPC UA Client, O=OPC UA Client, C=US
  Application URI: urn:opcua:client:app
  Valid From:      2026-02-05T10:00:00Z
  Valid Until:     2027-02-05T10:00:00Z
  Key Size:        2048 bits
  DNS Names:       localhost
  IP Addresses:    [127.0.0.1]

Usage:
  edgeo-opcua discovery -e <endpoint> -s Basic256Sha256 -m SignAndEncrypt --cert client-cert.pem --key client-key.pem
```

## Command: version

Print the version number.

### Usage

```bash
edgeo-opcua version
```

**Sample output:**

```
edgeo-opcua version 1.0.0
```

## Environment Variables

Environment variables use the `OPCUA_` prefix:

```bash
export OPCUA_ENDPOINT=opc.tcp://192.168.1.100:4840
export OPCUA_TIMEOUT=10000
export OPCUA_SECURITY_POLICY=Basic256Sha256
export OPCUA_SECURITY_MODE=SignAndEncrypt
```

## Secured Connection Workflow

For connecting to an OPC UA server with security enabled, follow these steps:

### 1. Discover available endpoints

```bash
edgeo-opcua discovery -e opc.tcp://server:4840
```

### 2. Generate a client certificate

```bash
edgeo-opcua gencert --app-uri "urn:mycompany:myapp" --dns "myhost.local"
```

### 3. Trust the client certificate on the server

Copy the generated `client-cert.pem` to the server's trusted certificates directory. This step varies by server implementation.

### 4. Connect with security

```bash
edgeo-opcua browse -e opc.tcp://server:4840 \
  -s Basic256Sha256 \
  -m SignAndEncrypt \
  --cert client-cert.pem \
  --key client-key.pem
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (connection failed, read/write failed, invalid arguments, etc.) |

## See Also

- [Client Library Documentation](client.md)
- [Server Documentation](server.md)
- [Configuration Options](options.md)
