var token =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJleHAiOjEzOTMyODY4OTMsImlhdCI6MTM5MzI2ODg5M30.4-iaDojEVl0pJQMjrbM1EzUIfAZgsbK_kgnVyVxFSVo";

if (typeof jwt_decode === "undefined") {
    var jwt_decode = require("../build/jwt-decode-non-json.cjs.js");
}

if (typeof expect === "undefined") {
    var expect = require("expect.js");
}

describe("jwt-decode-non-json", function() {
    it("should fail to construct without a clientID", function() {
        var decoded = jwt_decode(token);
        expect(decoded.exp).to.equal(1393286893);
        expect(decoded.iat).to.equal(1393268893);
        expect(decoded.foo).to.equal("bar");
    });

    it("should return header information", function() {
        var decoded = jwt_decode(token, { header: true });
        expect(decoded.typ).to.equal("JWT");
        expect(decoded.alg).to.equal("HS256");
    });

    it("should work with utf8 tokens", function() {
        var utf8_token =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9zw6kiLCJpYXQiOjE0MjU2NDQ5NjZ9.1CfFtdGUPs6q8kT3OGQSVlhEMdbuX0HfNSqum0023a0";
        var decoded = jwt_decode(utf8_token);
        expect(decoded.name).to.equal("José");
    });

    it("should work with binary tokens", function() {
        var binary_token =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9z6SIsImlhdCI6MTQyNTY0NDk2Nn0.cpnplCBxiw7Xqz5thkqs4Mo_dymvztnI0CI4BN0d1t8";
        var decoded = jwt_decode(binary_token);
        expect(decoded.name).to.equal("José");
    });

    it("should throw InvalidTokenError on nonstring", function() {
        var bad_token = null;
        expect(function() {
            jwt_decode(bad_token);
        }).to.throwException(function(e) {
            expect(e.name).to.be("InvalidTokenError");
        });
    });

    it("should throw InvalidTokenError on string that is not a token", function() {
        var bad_token = "fubar";
        expect(function() {
            jwt_decode(bad_token);
        }).to.throwException(function(e) {
            expect(e.name).to.be("InvalidTokenError");
        });
    });

    it("should work with non-json tokens", function() {
        const non_json_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.UnVsZXMgYW5kIG1vZGVscyBkZXN0cm95IGdlbml1cyBhbmQgYXJ0._ANvyRTNrsxp4M09FGQB0QdmYqXshi3bT9rqxvl1eco";
        const decoded = jwt_decode(non_json_token);
        expect(decoded).to.equal("Rules and models destroy genius and art");
    });

    it("should parse float and int tokens", function() {
        const int_json_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MTkxMg._lcpV8ypFTOl83ZlOQpEMmNwTfjNFAEfLcx6-5tMF_0";
        const decoded_int = jwt_decode(int_json_token);
        expect(decoded_int).to.equal(1912);

        const float_json_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MTkxMi41MTc4NTcxNDI5.ujrqVchIdQIPnbdv24x5mF-qx01CzDMfyItIicjgFKs";
        const decoded_float = jwt_decode(float_json_token);
        expect(decoded_float).to.equal(1912.5178571429);
    });
});