-- Version-controlled copy of the tiered-processing database migration applied to Supabase.
alter table public.usage_ledger
  add column if not exists job_credits_remaining integer not null default 2;

alter table public.usage_ledger drop constraint if exists usage_ledger_job_credits_remaining_check;
alter table public.usage_ledger
  add constraint usage_ledger_job_credits_remaining_check check (job_credits_remaining >= 0);

update public.usage_ledger u
set job_credits_remaining = greatest(
  0,
  (case p.current_tier
    when 'tier_1_51' then 30
    when 'tier_2_83' then 300
    when 'tier_3_129' then 1500
    else 2
  end) - u.total_lifetime_jobs
)
from public.profiles p
where p.user_id = u.profile_id;

alter table public.paypal_orders drop constraint if exists paypal_orders_amount_check;
alter table public.paypal_orders add constraint paypal_orders_amount_check
  check (amount in (51.00,83.00,129.00,79.00,149.00,299.00));

create or replace function public.complete_automation_job(
  p_user_id uuid, p_job_type text, p_input_filename text, p_result jsonb
)
returns jsonb language plpgsql security invoker set search_path = public
as $$
declare
  job_id uuid;
  remaining integer;
  lifetime integer;
  monthly integer;
begin
  update public.usage_ledger
     set job_credits_remaining = job_credits_remaining - 1,
         monthly_credits_used = monthly_credits_used + 1,
         total_lifetime_jobs = total_lifetime_jobs + 1
   where profile_id = p_user_id and job_credits_remaining > 0
  returning job_credits_remaining, total_lifetime_jobs, monthly_credits_used
       into remaining, lifetime, monthly;

  if not found then raise exception 'No job credits remain for this account'; end if;

  insert into public.automation_jobs(profile_id, job_type, input_filename, status, result, completed_at)
  values (p_user_id, p_job_type, p_input_filename, 'completed', coalesce(p_result, '{}'::jsonb), now())
  returning id into job_id;

  return jsonb_build_object('job_id', job_id, 'job_credits_remaining', remaining,
    'total_lifetime_jobs', lifetime, 'monthly_credits_used', monthly);
end;
$$;
revoke all on function public.complete_automation_job(uuid, text, text, jsonb) from public, anon, authenticated;
grant execute on function public.complete_automation_job(uuid, text, text, jsonb) to service_role;

create or replace function public.apply_paypal_capture(
  p_user_id uuid, p_transaction_id text, p_amount_paid numeric, p_assigned_tier public.subscription_tier
)
returns jsonb language plpgsql security invoker set search_path = public
as $$
declare
  inserted_transaction_id uuid;
  existing public.transactions%rowtype;
  credits_to_add integer;
  target_tier public.subscription_tier;
begin
  if p_transaction_id is null or length(trim(p_transaction_id)) = 0 then raise exception 'PayPal transaction ID is required'; end if;
  if p_amount_paid not in (79.00, 149.00, 299.00, 51.00, 83.00, 129.00) then raise exception 'Unsupported PayPal amount'; end if;
  if (p_amount_paid in (79.00,51.00) and p_assigned_tier <> 'tier_1_51')
     or (p_amount_paid in (149.00,83.00) and p_assigned_tier <> 'tier_2_83')
     or (p_amount_paid in (299.00,129.00) and p_assigned_tier <> 'tier_3_129') then
    raise exception 'Payment amount and tier do not match';
  end if;

  credits_to_add := case p_assigned_tier when 'tier_1_51' then 30 when 'tier_2_83' then 300 when 'tier_3_129' then 1500 else 0 end;
  insert into public.transactions(profile_id, payment_gateway, gateway_transaction_id, amount_paid)
  values (p_user_id, 'paypal', p_transaction_id, p_amount_paid)
  on conflict (gateway_transaction_id) do nothing
  returning transaction_id into inserted_transaction_id;

  if inserted_transaction_id is null then
    select * into existing from public.transactions where gateway_transaction_id = p_transaction_id;
    if existing.payment_gateway <> 'paypal' or existing.profile_id <> p_user_id or existing.amount_paid <> p_amount_paid then
      raise exception 'PayPal transaction ID conflicts with a different payment record';
    end if;
    return jsonb_build_object('success', true, 'duplicate', true, 'transaction_id', p_transaction_id);
  end if;

  select current_tier into target_tier from public.profiles where user_id = p_user_id for update;
  if not found then raise exception 'Profile not found for verified payment'; end if;
  if target_tier = 'tier_3_129' or p_assigned_tier = 'tier_3_129' then target_tier := 'tier_3_129';
  elsif target_tier = 'tier_2_83' or p_assigned_tier = 'tier_2_83' then target_tier := 'tier_2_83';
  else target_tier := 'tier_1_51'; end if;

  update public.profiles set current_tier = target_tier, status = 'active' where user_id = p_user_id;
  update public.usage_ledger set job_credits_remaining = job_credits_remaining + credits_to_add, last_reset_date = now()
   where profile_id = p_user_id;
  if not found then raise exception 'Usage ledger not found for verified payment'; end if;

  return jsonb_build_object('success', true, 'duplicate', false, 'transaction_id', p_transaction_id,
    'tier', target_tier, 'job_credits_added', credits_to_add);
end;
$$;
revoke all on function public.apply_paypal_capture(uuid, text, numeric, public.subscription_tier) from public, anon, authenticated;
grant execute on function public.apply_paypal_capture(uuid, text, numeric, public.subscription_tier) to service_role;
