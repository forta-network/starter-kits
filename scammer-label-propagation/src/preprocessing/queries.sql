-- get_related_addresses

select distinct
  address
from
  (
    select distinct
      from_address as address
    from
      ethereum.raw.traces
    where
      (
        from_address = '{{address}}'
        or to_address = '{{address}}'
      )
      and value > 0
      and block_timestamp <= to_timestamp ('{{tt}}')
    union all
    select distinct
      to_address as address
    from
      ethereum.raw.traces
    where
      (
        from_address = '{{address}}'
        or to_address = '{{address}}'
      )
      and value > 0
      and block_timestamp <= to_timestamp ('{{tt}}')
    union all
    select distinct
      from_address as address
    from
      ethereum.assets.erc20_token_transfers
    where
      (
        TRANSACTION_FROM_ADDRESS = '{{address}}'
        or from_address = '{{address}}'
        or to_address = '{{address}}'
      )
      and to_address != '0x0000000000000000000000000000000000000000'
      and from_address != '0x0000000000000000000000000000000000000000'
      and block_timestamp <= to_timestamp ('{{tt}}')
    union all
    select distinct
      to_address as address
    from
      ethereum.assets.erc20_token_transfers
    where
      (
        TRANSACTION_FROM_ADDRESS = '{{address}}'
        or from_address = '{{address}}'
        or to_address = '{{address}}'
      )
      and to_address != '0x0000000000000000000000000000000000000000'
      and from_address != '0x0000000000000000000000000000000000000000'
      and block_timestamp <= to_timestamp ('{{tt}}')
  )

-- all_eth_transactions

select
  from_address,
  to_address,
  count(value) as n_transactions_together,
  max(value) / 10e18 as max_value_together_eth,
  avg(value) / 10e18 as avg_value_together_eth,
  sum(value) / 10e18 as total_value_together
from
  ethereum.raw.traces
where
  from_address in {{addresses}}
  and to_address in {{addresses}}
  and value > 0
  and block_timestamp <= to_timestamp ('{{tt}}')
group by
  from_address,
  to_address
having
  n_transactions_together < 500

-- all_erc20_transactions
select
  from_address,
  to_address,
  count(usd_amount) as n_transactions_together_erc20,
  max(usd_amount) as max_usd_together_erc20,
  avg(usd_amount) as avg_usd_together_erc20,
  sum(usd_amount) as total_usd_together_erc20
from
  ethereum.assets.erc20_token_transfers
where
  from_address in {{addresses}}
  and to_address in {{addresses}}
  and to_address != '0x0000000000000000000000000000000000000000'
  and from_address != '0x0000000000000000000000000000000000000000'
  and block_timestamp <= to_timestamp ('{{tt}}')
group by
  from_address,
  to_address

-- eth_out

select
  from_address as address,
  count(value) as n_transactions_out_eth,
  max(value) / 10e18 as max_value_out_eth,
  avg(value) / 10e18 as avg_value_out_eth,
  sum(value) / 10e18 as total_value_out_eth
from
  ethereum.raw.traces
where
  address in {{addresses}}
  and value > 0
  and block_timestamp <= to_timestamp ('{{tt}}')
group by
  address
having
  n_transactions_out_eth < 5000

-- eth_in

select
  to_address as address,
  count(value) as n_transactions_in_eth,
  max(value) / 10e18 as max_value_in_eth,
  avg(value) / 10e18 as avg_value_in_eth,
  sum(value) / 10e18 as total_value_in_eth
from
  ethereum.raw.traces
where
  address in {{addresses}}
  and value > 0
  and block_timestamp <= to_timestamp ('{{tt}}')
group by
  address
having
  n_transactions_in_eth < 5000

-- erc20_out

select
  from_address as address,
  count(usd_amount) as n_transactions_out_erc20,
  max(usd_amount) as max_usd_out_erc20,
  avg(usd_amount) as avg_usd_out_erc20,
  sum(usd_amount) as total_usd_out_erc20
from
  ethereum.assets.erc20_token_transfers
where
  address in {{addresses}}
  and to_address != '0x0000000000000000000000000000000000000000'
  and from_address != '0x0000000000000000000000000000000000000000'
  and block_timestamp <= to_timestamp ('{{tt}}')
group by
  address
having
  n_transactions_out_erc20 < 5000
  and n_transactions_out_erc20 > 0

-- erc20_in

select
  to_address as address,
  count(usd_amount) as n_transactions_in_erc20,
  max(usd_amount) as max_usd_in_erc20,
  avg(usd_amount) as avg_usd_in_erc20,
  sum(usd_amount) as total_usd_in_erc20
from
  ethereum.assets.erc20_token_transfers
where
  address in {{addresses}}
  and to_address != '0x0000000000000000000000000000000000000000'
  and from_address != '0x0000000000000000000000000000000000000000'
  and block_timestamp <= to_timestamp ('{{tt}}')
group by
  address
having 
  n_transactions_in_erc20 < 5000
  and n_transactions_in_erc20 > 0
