LUABASE_QUERY = {1: "SELECT DISTINCT address, tag FROM ethereum.tags WHERE tag like '%xploit%' or tag like '%hishing%' or label='exploit' or label='heist' or label='phish-hack'",  # ethereum mainnet 
                137: "SELECT DISTINCT address, tag FROM polygon.tags WHERE tag like '%xploit%' or tag like '%hishing%' or label='exploit' or label='heist' or label='phish-hack'"  # polygon 
                }
