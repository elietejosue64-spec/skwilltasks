-- WILTASKS: cole no Supabase > SQL Editor > Run
create table profiles(
  id uuid primary key references auth.users on delete cascade,
  name text not null, email text, invite_code text unique not null,
  invited_by text, balance numeric(12,2) not null default 0 check (balance>=0),
  wallet text, blocked boolean not null default false,
  violations int not null default 0, is_admin boolean not null default false,
  created_at timestamptz default now());
create table tasks(
  id uuid primary key default gen_random_uuid(), title text not null,
  description text, reward numeric(12,2) not null check (reward>0),
  active boolean default true, created_at timestamptz default now());
create table submissions(
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles on delete cascade,
  task_id uuid not null references tasks on delete cascade,
  photo_path text not null, status text not null default 'pending'
    check (status in ('pending','approved','rejected')),
  reason text, created_at timestamptz default now(), reviewed_at timestamptz,
  unique(user_id,task_id));
create table withdrawals(
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles on delete cascade,
  amount numeric(12,2) not null, wallet text not null,
  status text not null default 'pending' check (status in ('pending','paid','rejected')),
  txhash text, created_at timestamptz default now());
create table notifications(
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles on delete cascade,
  message text not null, read boolean default false, created_at timestamptz default now());

create function is_admin() returns boolean language sql security definer stable
as $$ select coalesce((select is_admin from profiles where id=auth.uid()),false) $$;

-- Perfil automático no registo (código de convite obrigatório, exceto o 1.º utilizador = você)
create function handle_new_user() returns trigger language plpgsql security definer as $$
declare code text := upper(trim(coalesce(new.raw_user_meta_data->>'invite',''))); first_user boolean;
begin
  select not exists(select 1 from profiles) into first_user;
  if not first_user and not exists(select 1 from profiles where invite_code=code) then
    raise exception 'Código de convite inválido'; end if;
  insert into profiles(id,name,email,invite_code,invited_by,is_admin)
  values(new.id,coalesce(new.raw_user_meta_data->>'name','Utilizador'),new.email,
    'WIL'||upper(substr(md5(random()::text||new.id::text),1,6)),
    nullif(code,''),first_user);
  return new; end $$;
create trigger on_auth_user after insert on auth.users
  for each row execute function handle_new_user();

-- RLS: utilizadores NUNCA escrevem em profiles/withdrawals/saldo diretamente
alter table profiles enable row level security;
alter table tasks enable row level security;
alter table submissions enable row level security;
alter table withdrawals enable row level security;
alter table notifications enable row level security;
create policy p_sel on profiles for select using (id=auth.uid() or is_admin());
create policy t_sel on tasks for select using (active or is_admin());
create policy t_adm on tasks for all using (is_admin()) with check (is_admin());
create policy s_sel on submissions for select using (user_id=auth.uid() or is_admin());
create policy s_ins on submissions for insert with check (
  user_id=auth.uid() and status='pending' and not exists
  (select 1 from profiles where id=auth.uid() and blocked));
create policy w_sel on withdrawals for select using (user_id=auth.uid() or is_admin());
create policy n_sel on notifications for select using (user_id=auth.uid());
create policy n_upd on notifications for update using (user_id=auth.uid());

create function set_wallet(w text) returns void language plpgsql security definer as $$
begin
  if w !~ '^0x[a-fA-F0-9]{40}$' then raise exception 'Endereço BEP20 inválido'; end if;
  update profiles set wallet=w where id=auth.uid(); end $$;

create function request_withdrawal(amt numeric) returns void language plpgsql security definer as $$
declare p profiles;
begin
  select * into p from profiles where id=auth.uid() for update;
  if p.blocked then raise exception 'Conta bloqueada'; end if;
  if p.wallet is null then raise exception 'Defina a carteira BEP20'; end if;
  if amt < 0.20 then raise exception 'Mínimo 0,20 USDT'; end if;
  if amt > p.balance then raise exception 'Saldo insuficiente'; end if;
  update profiles set balance=balance-amt where id=p.id;
  insert into withdrawals(user_id,amount,wallet) values(p.id,round(amt,2),p.wallet); end $$;

create function review_submission(sid uuid, approve boolean, why text) returns void
language plpgsql security definer as $$
declare s submissions; r numeric;
begin
  if not is_admin() then raise exception 'Acesso negado'; end if;
  select * into s from submissions where id=sid and status='pending' for update;
  if not found then raise exception 'Já analisada'; end if;
  if approve then
    select reward into r from tasks where id=s.task_id;
    update profiles set balance=balance+r where id=s.user_id;
    update submissions set status='approved',reviewed_at=now() where id=sid;
    insert into notifications(user_id,message) values(s.user_id,'Tarefa aprovada: +'||r||' USDT');
  else
    if coalesce(trim(why),'')='' then raise exception 'Motivo obrigatório'; end if;
    update submissions set status='rejected',reason=why,reviewed_at=now() where id=sid;
    insert into notifications(user_id,message) values(s.user_id,'Tarefa rejeitada: '||why);
  end if; end $$;

create function resolve_withdrawal(wid uuid, paid boolean, tx text) returns void
language plpgsql security definer as $$
declare w withdrawals;
begin
  if not is_admin() then raise exception 'Acesso negado'; end if;
  select * into w from withdrawals where id=wid and status='pending' for update;
  if not found then raise exception 'Já resolvido'; end if;
  if paid then
    if coalesce(trim(tx),'')='' then raise exception 'Hash da transação obrigatório'; end if;
    update withdrawals set status='paid',txhash=trim(tx) where id=wid;
    insert into notifications(user_id,message) values(w.user_id,'Pagamento enviado: '||w.amount||' USDT');
  else
    update withdrawals set status='rejected' where id=wid;
    update profiles set balance=balance+w.amount where id=w.user_id;
    insert into notifications(user_id,message) values(w.user_id,'Levantamento rejeitado; valor devolvido ao saldo.');
  end if; end $$;

create function moderate_user(uid uuid, block boolean, add_violation boolean) returns void
language plpgsql security definer as $$
begin
  if not is_admin() then raise exception 'Acesso negado'; end if;
  update profiles set blocked=block, violations=violations+(case when add_violation then 1 else 0 end)
  where id=uid and not is_admin; end $$;

-- Armazenamento privado das fotografias
insert into storage.buckets(id,name,public) values('proofs','proofs',false);
create policy up on storage.objects for insert to authenticated
  with check (bucket_id='proofs' and (storage.foldername(name))[1]=auth.uid()::text);
create policy rd on storage.objects for select to authenticated
  using (bucket_id='proofs' and ((storage.foldername(name))[1]=auth.uid()::text or is_admin()));
