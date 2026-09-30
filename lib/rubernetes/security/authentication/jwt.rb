# frozen_string_literal: true

require "base64"
require "json"
require "openssl"

module Rubernetes
  module Security
    module Authentication
      # Minimal JWS/JWT implementation for RS256/RS384/RS512/ES256/ES384/ES512/
      # HS256..512 used by the ServiceAccount issuer and the OIDC/JWT
      # authenticator.  `none` is rejected.  Header and claims are parsed
      # strictly (JSON objects, no duplicate keys via canonical decode).
      module JWT
        class Error < AuthenticationError; end

        ALGORITHMS = {
          "RS256" => [:rsa, "SHA256"], "RS384" => [:rsa, "SHA384"], "RS512" => [:rsa, "SHA512"],
          "PS256" => [:rsa_pss, "SHA256"], "PS384" => [:rsa_pss, "SHA384"], "PS512" => [:rsa_pss, "SHA512"],
          "ES256" => [:ec, "SHA256"], "ES384" => [:ec, "SHA384"], "ES512" => [:ec, "SHA512"],
          "HS256" => [:hmac, "SHA256"], "HS384" => [:hmac, "SHA384"], "HS512" => [:hmac, "SHA512"]
        }.freeze

        module_function

        def encode_segment(value)
          Base64.urlsafe_encode64(value, padding: false)
        end

        def decode_segment(segment)
          raise Error, "jwt: segment is not base64url" unless segment.match?(/\A[A-Za-z0-9_-]*\z/)

          Base64.urlsafe_decode64(segment)
        rescue ArgumentError
          raise Error, "jwt: segment is not base64url"
        end

        def sign(claims, key:, algorithm:, key_id: nil)
          kind, digest = ALGORITHMS.fetch(algorithm) { raise Error, "jwt: unsupported algorithm #{algorithm}" }
          header = {"alg" => algorithm, "typ" => "JWT"}
          header["kid"] = key_id if key_id
          signing_input = "#{encode_segment(JSON.generate(header))}.#{encode_segment(JSON.generate(claims))}"
          signature = case kind
                      when :rsa then key.sign(OpenSSL::Digest.new(digest), signing_input)
                      when :rsa_pss then key.sign_pss(digest, signing_input, salt_length: :digest, mgf1_hash: digest)
                      when :ec then der_to_raw(key.sign(OpenSSL::Digest.new(digest), signing_input), key)
                      when :hmac then OpenSSL::HMAC.digest(digest, key, signing_input)
                      end
          "#{signing_input}.#{encode_segment(signature)}"
        end

        # Parse without verifying; returns [header, claims, signing_input, signature].
        def parse(token)
          parts = token.to_s.split(".", -1)
          raise Error, "jwt: token must have three segments" unless parts.length == 3

          header = JSON.parse(decode_segment(parts[0]))
          claims = JSON.parse(decode_segment(parts[1]))
          raise Error, "jwt: header and claims must be objects" unless header.is_a?(Hash) && claims.is_a?(Hash)

          [header, claims, "#{parts[0]}.#{parts[1]}", decode_segment(parts[2])]
        rescue JSON::ParserError => error
          raise Error, "jwt: invalid JSON: #{error.message}"
        end

        # Verify the signature with one of `keys` ({kid => key} or [key, ...]).
        def verify(token, keys:, allowed_algorithms: ALGORITHMS.keys)
          header, claims, signing_input, signature = parse(token)
          algorithm = header["alg"].to_s
          raise Error, "jwt: algorithm none is rejected" if algorithm.casecmp("none").zero? || algorithm.empty?
          raise Error, "jwt: algorithm #{algorithm} is not allowed" unless allowed_algorithms.include?(algorithm)

          kind, digest = ALGORITHMS.fetch(algorithm)
          candidates = candidate_keys(keys, header["kid"])
          raise Error, "jwt: no key matches kid #{header["kid"].inspect}" if candidates.empty?

          verified = candidates.any? { |key| verify_with(key, kind, digest, signing_input, signature) }
          raise Error, "jwt: signature verification failed" unless verified

          [header, claims]
        end

        def candidate_keys(keys, kid)
          if keys.is_a?(Hash)
            return [keys[kid]].compact if kid && keys.key?(kid)

            return kid ? [] : keys.values
          end
          Array(keys)
        end

        def verify_with(key, kind, digest, signing_input, signature)
          case kind
          when :rsa then key.is_a?(OpenSSL::PKey::RSA) && key.verify(OpenSSL::Digest.new(digest), signature, signing_input)
          when :rsa_pss then key.is_a?(OpenSSL::PKey::RSA) && key.verify_pss(digest, signature, signing_input, salt_length: :auto,
                                                                                                               mgf1_hash: digest)
          when :ec then key.is_a?(OpenSSL::PKey::EC) && key.verify(OpenSSL::Digest.new(digest), raw_to_der(signature, key), signing_input)
          when :hmac then key.is_a?(String) && secure_compare(OpenSSL::HMAC.digest(digest, key, signing_input), signature)
          else false
          end
        rescue OpenSSL::PKey::PKeyError
          false
        end

        def curve_bytes(key)
          case key.group.curve_name
          when "prime256v1", "secp256r1" then 32
          when "secp384r1" then 48
          when "secp521r1" then 66
          else raise Error, "jwt: unsupported curve #{key.group.curve_name}"
          end
        end

        def der_to_raw(der, key)
          sequence = OpenSSL::ASN1.decode(der)
          r, s = sequence.value.map { |integer| integer.value.to_s(2) }
          size = curve_bytes(key)
          r.rjust(size, "\0") + s.rjust(size, "\0")
        end

        def raw_to_der(raw, key)
          size = curve_bytes(key)
          raise Error, "jwt: invalid ECDSA signature length" unless raw.bytesize == size * 2

          r = OpenSSL::BN.new(raw.byteslice(0, size), 2)
          s = OpenSSL::BN.new(raw.byteslice(size, size), 2)
          OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]).to_der
        end

        def secure_compare(left, right)
          return false unless left.bytesize == right.bytesize

          result = 0
          left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
          result.zero?
        end

        # RFC 7638 JWK thumbprint used as the default key id.
        def key_id(public_key)
          jwk = to_jwk(public_key)
          canonical = case jwk["kty"]
                      when "RSA" then {"e" => jwk["e"], "kty" => "RSA", "n" => jwk["n"]}
                      when "EC" then {"crv" => jwk["crv"], "kty" => "EC", "x" => jwk["x"], "y" => jwk["y"]}
                      end
          encode_segment(OpenSSL::Digest::SHA256.digest(JSON.generate(canonical)))
        end

        def to_jwk(public_key)
          case public_key
          when OpenSSL::PKey::RSA
            {"kty" => "RSA", "n" => encode_segment(public_key.n.to_s(2)), "e" => encode_segment(public_key.e.to_s(2))}
          when OpenSSL::PKey::EC
            point = public_key.public_key.to_octet_string(:uncompressed)
            size = curve_bytes(public_key)
            {"kty" => "EC", "crv" => {32 => "P-256", 48 => "P-384", 66 => "P-521"}.fetch(size),
             "x" => encode_segment(point.byteslice(1, size)), "y" => encode_segment(point.byteslice(1 + size, size))}
          else
            raise Error, "jwt: unsupported key type #{public_key.class}"
          end
        end

        def from_jwk(jwk)
          case jwk["kty"]
          when "RSA"
            n = OpenSSL::BN.new(decode_segment(jwk.fetch("n")), 2)
            e = OpenSSL::BN.new(decode_segment(jwk.fetch("e")), 2)
            OpenSSL::PKey::RSA.new(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(n), OpenSSL::ASN1::Integer.new(e)]).to_der)
          when "EC"
            curve = {"P-256" => "prime256v1", "P-384" => "secp384r1", "P-521" => "secp521r1"}.fetch(jwk.fetch("crv"))
            group = OpenSSL::PKey::EC::Group.new(curve)
            point = OpenSSL::PKey::EC::Point.new(group,
                                                 OpenSSL::BN.new(
                                                   "\x04".b + decode_segment(jwk.fetch("x")) + decode_segment(jwk.fetch("y")), 2
                                                 ))
            asn1 = OpenSSL::ASN1::Sequence.new([
                                                 OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"), OpenSSL::ASN1::ObjectId.new(curve)]),
                                                 OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed))
                                               ])
            OpenSSL::PKey::EC.new(asn1.to_der)
          else
            raise Error, "jwt: unsupported JWK type #{jwk["kty"].inspect}"
          end
        end
      end
    end
  end
end
