# mjölnir

The JWT hammer

## Usage

### Dictionary attack against HMAC signature

`mjolnir -jwt $JWToken -dic myDict.txt`

For example, use the rockyou dictionary against this JWT:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABn9EFDMlzoAMvhxq0XPsYzR3h5ro9t4k-ulGCG7J1c
```

### Signature exclusion attack

`mjolnir -jwt $JWToken -exclude`