rule RULE_NAME {
    meta:
        author = "YOUR_NAME"
        create_date = "YYYY-MM-DD"
        modified_date = "YYYY-MM-DD"
        hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
        hash2 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
        hash3 = "2c10b2ec0b995b88c27d141d6f7b14d6b8177c52818687e4ff8e6ecf53adf5bf"
        hash4 = "3c557727953a8f6b4788984464fb77741b821991acbf5e746aebdd02615b1767"
        hash5 = "a64c3e0522fad787b95bfb6a30c3aed1b5786e69e88e023c062ec7e5cebf4d3e"
        hash6 = "06086c1da4590dcc7f1e10a6be3431e1166286a9e7761f2de9de79d7fda9c397"
        description = ""
    strings:
        $s1 = "ADD YOUR SIGNATURE HERE"
    condition:
        uint16(0) == 0x5a4d and // MZ
        uint32(uint32(0x3c)) == 0x00004550 and //PE
        all of them // REPLACE HERE
}