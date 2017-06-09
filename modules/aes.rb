require 'base64'
require 'openssl'

# AES : Encrypt/Decrypt blocks of data with AES encryption standard
module AES

    # Encrypts a block of data given an encryption key and an
    # initialization vector (iv).
    # Pass nil for the iv if the encryption type doesn't use iv's.
    #
    # * *Args* :
    #   - +data+ -> message string to be encrypted
    #   - +key+ -> string encryption key
    #   - +iv+ -> string initialization vector
    #   - +cipher_type+ -> block cipher mode of operation supported by OpenSSL (http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation)
    #
    # _Example_ :
    #   KEY = "735b255b3c7e5e48483166784bff34fb"
    #   IV = "615c7e78595b647e4d683f7127"
    #   AES.encrypt("my secret message in plain text", KEY, IV, "AES-256-CBC")
    #
    def AES.encrypt(data, key, iv, cipher_type)
        aes = OpenSSL::Cipher::Cipher.new(cipher_type)
        aes.encrypt
        aes.key = key
        aes.iv = iv if iv != nil
        aes.update(data) + aes.final
    end

    # Decrypts a block of data (cipher) given an encryption key
    # and an initialization vector (iv).
    # Pass nil for the iv if the encryption type doesn't use iv's.
    #
    # * *Args* :
    #   - +cipher+ -> cipher text as string
    #   - +key+ -> string encryption key
    #   - +iv+ -> string initialization vector
    #   - +cipher_type+ -> block cipher mode of operation supported by OpenSSL (http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation)
    #
    # _Example_ :
    #   KEY = "735b255b3c7e5e48483166784bff34fb"
    #   IV = "615c7e78595b647e4d683f7127"
    #   AES.decrypt("cipher text", KEY, IV, "AES-256-CBC")
    #
    def AES.decrypt(cipher, key, iv, cipher_type)
        aes = OpenSSL::Cipher::Cipher.new(cipher_type)
        aes.decrypt
        aes.key = key
        aes.iv = iv if iv != nil
        aes.update(cipher) + aes.final
    end


    # Encodes a cipher to base64 string.
    # Very useful for storing in DB's or text format storage types.
    #
    # * *Args* :
    #   - +cipher+ -> cipher text as string
    #
    # _Example_ :
    #   AES.base64encode("\xFBk\xB8\n{\x11{\xAD \xECV\bB\x01\xF9\xB8")
    #
    def AES.base64encode(cipher)
        Base64.encode64(cipher)
    end


    # Decodes a base64 string back to cipher.
    # Decoded cipher should be passed further to AES.decrypt method.
    #
    # * *Args* :
    #   - +str+ -> base64 encoded sting
    #
    # _Example_ :
    #   AES.base64decode("+2u4CnsRe60g7FYIQgH5uA==\n")
    #
    def AES.base64decode(str)
        Base64.decode64(str)
    end

end
