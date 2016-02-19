# hashers
All password hashing algorithms for Django implemented in javascript for nodejs projects.

# Usage

    var h = new UnsaltedSHA1PasswordHasher();
    var hash1 = h.encode("password", h.salt());
    console.log(h.verify("password", hash1)); // returns true
    console.log(h.verify("wrong_password", hash1)); // returns false
    
Similar approach to the above code sample can be used for all the other algorithms.

