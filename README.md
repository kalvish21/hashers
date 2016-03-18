# hashers
All password hashing algorithms for Django implemented in javascript for nodejs projects.

# Supported Algorithms

1. PBKDF2PasswordHasher
2. PBKDF2SHA1PasswordHasher
3. BCryptSHA256PasswordHasher
4. BCryptPasswordHasher
5. SHA1PasswordHasher
6. MD5PasswordHasher
7. UnsaltedSHA1PasswordHasher
8. UnsaltedMD5PasswordHasher
9. CryptPasswordHasher

# Usage

```javascript
var h = new PBKDF2PasswordHasher();
var hash1 = h.encode("password", h.salt());
console.log(h.verify("password", hash1)); // returns true
console.log(h.verify("wrong_password", hash1)); // returns false
```

Similar approach to the above code sample can be used for all the other algorithms.

# Installation
```ssh
npm install hashers
```
