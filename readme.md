# 1. Introduction

xcrypto - extend crypto for golang.

friendly interface to programmer.

# 2. Install
```bash
go get github.com/irelance/xcrypto
```

# 3. Support

## 3.1. rsa algorithm

support private key encrypt, private key decrypt, 
public key encrypt, public key decrypt.

auto detect key format from files

### 3.1.1. private key format

1. pkcs1 / pem
1. pkcs8

### 3.1.2. public key format

1. pkcs1 / pem
1. pkcs8

### 3.1.3. block crypto mode

1. EBC

### 3.1.4. padding

1. pkcs1v15

### 3.1.5. usage
[example](https://github.com/irelance/xcrypto/blob/master/rsa/simple_test.go#L26)

