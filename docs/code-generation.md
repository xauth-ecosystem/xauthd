# Code Generation from `xauth.proto`

Reference guide for generating gRPC client stubs and Protocol Buffers message classes from `proto/xauth.proto`.

## Dependencies

### `protoc` (Protocol Buffers compiler)

Required for all target languages.

```bash
# Fedora / RHEL
sudo dnf install protobuf-compiler

# Debian / Ubuntu
sudo apt install protobuf-compiler

# Manual — download from https://github.com/protocolbuffers/protobuf/releases
PB_VER="28.3"
curl -sLO "https://github.com/protocolbuffers/protobuf/releases/download/v${PB_VER}/protoc-${PB_VER}-linux-x86_64.zip"
unzip -o "protoc-${PB_VER}-linux-x86_64.zip" -d /tmp/protoc
sudo cp /tmp/protoc/bin/protoc /usr/local/bin/
```

Verify: `protoc --version`

### PHP gRPC runtime extensions

```bash
# Fedora / RHEL
sudo dnf install php-pecl-grpc php-pecl-protobuf

# Debian / Ubuntu
sudo apt install php-grpc

# Manual (PECL)
sudo pecl install grpc protobuf
```

Add to `php.ini`:

```ini
extension=grpc.so
extension=protobuf.so
```

### PHP Composer dependency

```bash
composer require grpc/grpc
```

### Java gRPC runtime dependency

Maven:

```xml
<dependency>
    <groupId>io.grpc</groupId>
    <artifactId>grpc-netty-shaded</artifactId>
    <version>1.68.0</version>
</dependency>
<dependency>
    <groupId>io.grpc</groupId>
    <artifactId>grpc-protobuf</artifactId>
    <version>1.68.0</version>
</dependency>
<dependency>
    <dependency>
        <groupId>io.grpc</groupId>
        <artifactId>grpc-stub</artifactId>
        <version>1.68.0</version>
    </dependency>
</dependency>
```

Gradle:

```groovy
implementation 'io.grpc:grpc-netty-shaded:1.68.0'
implementation 'io.grpc:grpc-protobuf:1.68.0'
implementation 'io.grpc:grpc-stub:1.68.0'
```

For protobuf code generation annotation support (Java ≥ 16):

```xml
<dependency>
    <groupId>javax.annotation</groupId>
    <artifactId>javax.annotation-api</artifactId>
    <version>1.3.2</version>
</dependency>
```

## PHP

### `grpc_php_plugin`

Required for generating gRPC service stubs. Not available as a system package — must be built from source.

#### Build dependencies

```bash
# Fedora / RHEL
sudo dnf install cmake gcc-c++ git

# Debian / Ubuntu
sudo apt install cmake g++ git
```

#### Build

```bash
git clone --depth 1 -b v1.68.0 https://github.com/grpc/grpc /tmp/grpc
cd /tmp/grpc
git submodule update --init
mkdir -p cmake/build && cd cmake/build
cmake ../.. -DCMAKE_POLICY_VERSION_MINIMUM=3.5
make grpc_php_plugin -j$(nproc)
sudo cp grpc_php_plugin /usr/local/bin/
```

The `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` flag is required on systems with CMake ≥ 3.31.

Verify: `which grpc_php_plugin`

#### Generate code

```bash
mkdir -p gen/php

protoc \
    --php_out=gen/php \
    --grpc_out=gen/php \
    --plugin=protoc-gen-grpc=$(which grpc_php_plugin) \
    --proto_path=proto \
    proto/xauth.proto
```

Output structure:

```
gen/php/
+-- ChernegaSergiy/XAuth/Grpc/
|   +-- AuthServiceClient.php         # gRPC client stub
|   +-- AuthStepRequest.php
|   +-- AuthStepResponse.php
|   +-- SessionRequest.php
|   +-- SessionResponse.php
|   +-- EndSessionRequest.php
|   +-- EndSessionResponse.php
|   +-- PluginEvent.php
|   +-- CoreCommand.php
|   +-- OAuthTokenRequest.php
|   +-- OAuthTokenResponse.php
|   +-- OAuthRevokeRequest.php
|   +-- OAuthRevokeResponse.php
|   +-- PlayerInfoRequest.php
|   +-- PlayerInfoResponse.php
|   +-- ForcePasswordChangeRequest.php
|   \-- ForcePasswordChangeResponse.php
\-- GPBMetadata/Xauth.php
```

### Usage

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';

use ChernegaSergiy\XAuth\Grpc\AuthServiceClient;
use ChernegaSergiy\XAuth\Grpc\AuthStepRequest;

$client = new AuthServiceClient('localhost:5091', [
    'credentials' => \Grpc\ChannelCredentials::createInsecure(),
]);

$request = new AuthStepRequest();
$request->setUsername('player1');
$request->setIpAddress('127.0.0.1');
$request->setServerId('server-1');
$request->setStepType('password');
$request->setInputData('my_password');
$request->setFlowToken('');

[$response, $status] = $client->ProcessAuthStep($request)->wait();
```

## Java

### `protoc-gen-grpc-java`

Required for generating Java gRPC service stubs. Download pre-built binary from Maven Central:

```bash
GRPC_JAVA_VER="1.68.0"
curl -sL "https://repo1.maven.org/maven2/io/grpc/protoc-gen-grpc-java/${GRPC_JAVA_VER}/protoc-gen-grpc-java-${GRPC_JAVA_VER}-linux-x86_64.exe" \
    -o /usr/local/bin/protoc-gen-grpc-java
chmod +x /usr/local/bin/protoc-gen-grpc-java
```

Available binaries: `linux-x86_64`, `linux-aarch_64`, `osx-x86_64`, `osx-aarch_64`, `windows-x86_64`.

#### Generate code

```bash
mkdir -p gen/java

protoc \
    --java_out=gen/java \
    --grpc-java_out=gen/java \
    --plugin=protoc-gen-grpc-java=$(which protoc-gen-grpc-java) \
    --proto_path=proto \
    proto/xauth.proto
```

Output structure:

```
gen/java/com/chernegasergiy/xauth/grpc/
+-- AuthServiceGrpc.java              # gRPC service stub
+-- AuthStepRequest.java
+-- AuthStepRequestOrBuilder.java
+-- AuthStepResponse.java
+-- AuthStepResponseOrBuilder.java
+-- SessionRequest.java
+-- SessionRequestOrBuilder.java
+-- SessionResponse.java
+-- SessionResponseOrBuilder.java
+-- EndSessionRequest.java
+-- EndSessionRequestOrBuilder.java
+-- EndSessionResponse.java
+-- EndSessionResponseOrBuilder.java
+-- PluginEvent.java
+-- PluginEventOrBuilder.java
+-- CoreCommand.java
+-- CoreCommandOrBuilder.java
+-- OAuthTokenRequest.java
+-- OAuthTokenRequestOrBuilder.java
+-- OAuthTokenResponse.java
+-- OAuthTokenResponseOrBuilder.java
+-- OAuthRevokeRequest.java
+-- OAuthRevokeRequestOrBuilder.java
+-- PlayerInfoRequest.java
+-- PlayerInfoRequestOrBuilder.java
+-- PlayerInfoResponse.java
+-- PlayerInfoResponseOrBuilder.java
+-- ForcePasswordChangeRequest.java
+-- ForcePasswordChangeRequestOrBuilder.java
+-- ForcePasswordChangeResponse.java
+-- ForcePasswordChangeResponseOrBuilder.java
\-- XAuthProto.java
```

### Usage

```java
import com.chernegasergiy.xauth.grpc.AuthServiceGrpc;
import com.chernegasergiy.xauth.grpc.AuthStepRequest;
import com.chernegasergiy.xauth.grpc.AuthStepResponse;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

ManagedChannel channel = ManagedChannelBuilder
    .forAddress("localhost", 5091)
    .usePlaintext()
    .build();

AuthServiceGrpc.AuthServiceBlockingStub stub =
    AuthServiceGrpc.newBlockingStub(channel);

AuthStepRequest request = AuthStepRequest.newBuilder()
    .setUsername("player1")
    .setIpAddress("127.0.0.1")
    .setServerId("server-1")
    .setStepType("password")
    .setInputData("my_password")
    .setFlowToken("")
    .build();

AuthStepResponse response = stub.processAuthStep(request);
System.out.println("Success: " + response.getSuccess());
```

## Troubleshooting

### `protoc-gen-grpc: program not found or is not executable`

The gRPC plugin binary is not in `PATH`. Use an absolute path in `--plugin=`:

```bash
--plugin=protoc-gen-grpc=/usr/local/bin/grpc_php_plugin
```

### `PHP Fatal error: Class 'Grpc\BaseStub' not found`

The `grpc` PHP extension is not installed or not loaded. Verify:

```bash
php -m | grep grpc
```

### `protoc-gen-grpc-java: program not found`

The Java gRPC plugin binary is not in `PATH`. Verify installation:

```bash
which protoc-gen-grpc-java
```

### CMake build fails with `CMake Error at third_party/cares/cares/CMakeLists.txt:1`

CMake ≥ 3.31 removed compatibility with `CMAKE_MINIMUM_REQUIRED` < 3.5. Add the flag:

```bash
cmake ../.. -DCMAKE_POLICY_VERSION_MINIMUM=3.5
```
