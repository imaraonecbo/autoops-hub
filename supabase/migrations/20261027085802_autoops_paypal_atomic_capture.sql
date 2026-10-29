-- Tables used by authenticated PayPal checkout and persisted customer reports.
create table if not exists public.paypal_orders (
  id uuid primary key default gen_random_uuid(),
  paypal_order_id text not null unique,
  user_id uuid not null references public.profiles(user_id) on delete cascade,
  tier public.subscription_tier not null,
  amount numeric(10,2) not null check (amount in (51.00,83.00,129.00)),
  status text not null default 'pending' check (status in ('pending','captured','failed')),
  capture_id text unique,
  created_at timestamptz not null default now(),
  captured_at timestamptz
);
alter table public.paypal_orders enable row level security;
revoke all on public.paypal_orders from anon, authenticated;
grant select, insert, update, delete on public.paypal_orders to service_role;
create index if not exists paypal_orders_user_created_idx on public.paypal_orders(user_id, created_at desc);

create table if not exists public.automation_jobs (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles(user_id) on delete cascade,
  job_type text not null,
  input_filename text not null,
  status text not null default 'completed' check (status in ('queued','running','completed','failed')),
  result jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);
alter table public.automation_jobs enable row level security;
revoke all on public.automation_jobs from anon, authenticated;
grant select, insert, update, delete on public.automation_jobs to service_role;
create index if not exists automation_jobs_profile_created_idx on public.automation_jobs(profile_id, created_at desc);

-- Applied to Supabase project erfkjxrcyfrvtqfnmuqq as migration
-- 20261027085802_autoops_paypal_atomic_capture.
-- Keep this file aligned with the deployed database migration.

create or replace function public.increment_lifetime_jobs(uid uuid)
returns void
language plpgsql
security invoker
set search_path = public
as $$
begin
  update public.usage_ledger
     set total_lifetime_jobs = total_lifetime_jobs + 1
   where profile_id = uid;
  if not found then
    raise exception 'Usage ledger not found for user';
  end if;
end;
$$;

revoke all on function public.increment_lifetime_jobs(uuid) from public, anon, authenticated;
grant execute on function public.increment_lifetime_jobs(uuid) to service_role;

create or replace function public.apply_paypal_capture(
  p_user_id uuid,
  p_transaction_id text,
  p_amount_paid numeric,
  p_assigned_tier public.subscription_tier
)
returns jsonb
language plpgsql
security invoker
set search_path = public
as $$
declare
  inserted_transaction_id uuid;
  existing public.transactions%rowtype;
begin
  if p_transaction_id is null or length(trim(p_transaction_id)) = 0 then
    raise exception 'PayPal transaction ID is required';
  end if;

  if p_amount_paid not in (51.00, 83.00, 129.00) then
    raise exception 'Unsupported PayPal amount';
  end if;

  if (p_amount_paid = 51.00 and p_assigned_tier <> 'tier_1_51')
     or (p_amount_paid = 83.00 and p_assigned_tier <> 'tier_2_83')
     or (p_amount_paid = 129.00 and p_assigned_tier <> 'tier_3_129') then
    raise exception 'Payment amount and tier do not match';
  end if;

  insert into public.transactions (
    profile_id, payment_gateway, gateway_transaction_id, amount_paid
  )
  values (
    p_user_id, 'paypal', p_transaction_id, p_amount_paid
  )
  on conflict (gateway_transaction_id) do nothing
  returning transaction_id into inserted_transaction_id;

  if inserted_transaction_id is null then
    select * into existing
      from public.transactions
     where gateway_transaction_id = p_transaction_id;

    if existing.payment_gateway <> 'paypal'
       or existing.profile_id <> p_user_id
       or existing.amount_paid <> p_amount_paid then
      raise exception 'PayPal transaction ID conflicts with a different payment record';
    end if;

    return jsonb_build_object(
      'success', true,
      'duplicate', true,
      'transaction_id', p_transaction_id
    );
  end if;

  update public.profiles
     set current_tier = p_assigned_tier,
         status = 'active'
   where user_id = p_user_id;

  if not found then
    raise exception 'Profile not found for verified payment';
  end if;

  update public.usage_ledger
     set monthly_credits_used = 0,
         last_reset_date = now()
   where profile_id = p_user_id;

  if not found then
    raise exception 'Usage ledger not found for verified payment';
  end if;

  return jsonb_build_object(
    'success', true,
    'duplicate', false,
    'transaction_id', p_transaction_id,
    'tier', p_assigned_tier
  );
end;
$$;

revoke all on function public.apply_paypal_capture(uuid, text, numeric, public.subscription_tier) from public, anon, authenticated;
grant execute on function public.apply_paypal_capture(uuid, text, numeric, public.subscription_tier) to service_role;
