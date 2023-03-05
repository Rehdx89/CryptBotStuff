rule CryptBot_Crypter
{
    meta:
        author = "Rhedx89"
        description = "Supposed to detect cyptbot samples"
        hash = "1e0e5d2ccfcf86beddebaa1a8eec2ca5a3c7db89c3db255de215530f7e6daf4e"
    

    strings:
        $decryption = {80 7d 18 00 74 0d 6a 03 33 d2
                       8b c6 59 f7 f1 85 d2 75 2c 33
                       c9 8d 47 01 3b 7d 14 0f 45 c8
                       0f b6 04 1e 8b f9 8b 4d 10 0f
                       b6 14 0f 33 c9 33 c1 41 81 f9 
                       ff 00 00 00 7c f5 32 c2 34 0f
                       88 04 1e 46 3b 75 0c 72 bb}
                       
        $fetchInPEB = {52 50 8b 55 f8 2b 55 08 8b ?? 0c 8b ?? 0c}

    condition:
        $decryption and $fetchInPEB
}


